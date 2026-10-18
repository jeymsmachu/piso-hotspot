//! Root-only integration test for the kernel enforcement path.
//!
//! The unit tests around the paywall use a fake `nft`; this one runs the
//! real thing against the real kernel, in throwaway network namespaces,
//! because "an unauthorized device cannot reach the internet" is the
//! promise the product is built on and a fake cannot prove it.
//!
//! It needs root (namespaces, nftables, `ip_forward`) and skips itself
//! with a note when it does not have it, so `cargo test` stays usable for
//! everyone. CI runs it as root:
//!
//! ```console
//! sudo cargo test --locked netns -- --nocapture
//! ```
//!
//! Layout: a client namespace and a server namespace, joined by a router
//! namespace that runs the paywall exactly as the daemon would. Traffic
//! from the client to the server crosses the router's `forward` chain —
//! the chain that decides whether a device has internet.

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::process::Command;

    use crate::nft::{Firewall, SetChange, SetName};

    struct Netns(String);

    impl Netns {
        fn new(name: &str) -> Self {
            run("ip", &["netns", "add", name]);
            Self(name.to_string())
        }

        /// Run a command inside this namespace.
        fn exec(&self, program: &str, args: &[&str]) -> bool {
            let mut full = vec!["netns", "exec", self.0.as_str(), program];
            full.extend_from_slice(args);
            run("ip", &full)
        }

        fn output(&self, program: &str, args: &[&str]) -> String {
            let mut full = vec!["netns", "exec", self.0.as_str(), program];
            full.extend_from_slice(args);
            let out = Command::new("ip").args(&full).output().expect("spawn");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
    }

    impl Drop for Netns {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
        }
    }

    fn run(program: &str, args: &[&str]) -> bool {
        Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn have(program: &str) -> bool {
        Command::new(program).arg("--version").output().is_ok()
            || Command::new(program).arg("-V").output().is_ok()
    }

    /// Move this thread into a namespace: children spawned from here run
    /// inside it, which is how the paywall sees the router's kernel.
    fn enter(namespace: &str) -> bool {
        use std::os::fd::AsRawFd;
        let path = format!("/var/run/netns/{namespace}");
        let Ok(file) = std::fs::File::open(&path) else {
            return false;
        };
        unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) == 0 }
    }

    fn reachable(target: &str) -> bool {
        run("ping", &["-c", "1", "-W", "1", target])
    }

    /// The table as the reconciler sees it. Panics when the table is not
    /// installed or not ours: in this test that is a failure, not a state.
    fn installed_table(fw: &Firewall) -> crate::nft::TableSnapshot {
        fw.inspect()
            .expect("reading the table")
            .expect("the paywall is installed and intact")
    }

    #[test]
    fn kernel_path_is_fail_closed_and_repairs_itself() {
        if !crate::doctor::is_root() {
            eprintln!("skipped: the kernel enforcement test needs root (sudo cargo test)");
            return;
        }
        for tool in ["ip", "nft", "ping"] {
            if !have(tool) {
                eprintln!("skipped: {tool} is not installed");
                return;
            }
        }

        let pid = std::process::id();
        let (client, router, server) = (
            format!("piso-c-{pid}"),
            format!("piso-r-{pid}"),
            format!("piso-s-{pid}"),
        );
        let _client_ns = Netns::new(&client);
        let _router_ns = Netns::new(&router);
        let _server_ns = Netns::new(&server);

        // Two links: client ↔ router (the "AP" side) and router ↔ server
        // (the "uplink" side). Each pair has one end on a leaf namespace
        // and one end on the router.
        for (leaf_ns, leaf_end, router_end) in [
            (client.as_str(), "vc0", "vr0"),
            (server.as_str(), "vs0", "vr1"),
        ] {
            assert!(
                run(
                    "ip",
                    &[
                        "link", "add", leaf_end, "type", "veth", "peer", "name", router_end
                    ]
                ),
                "creating the veth pair {leaf_end}/{router_end}"
            );
            assert!(
                run("ip", &["link", "set", leaf_end, "netns", leaf_ns]),
                "moving {leaf_end} into {leaf_ns}"
            );
            assert!(
                run("ip", &["link", "set", router_end, "netns", &router]),
                "moving {router_end} into {router}"
            );
        }

        // Addresses and routes.
        _client_ns.exec("ip", &["addr", "add", "10.99.0.2/24", "dev", "vc0"]);
        _client_ns.exec("ip", &["link", "set", "vc0", "up"]);
        _client_ns.exec("ip", &["link", "set", "lo", "up"]);
        _client_ns.exec("ip", &["route", "add", "default", "via", "10.99.0.1"]);
        _server_ns.exec("ip", &["addr", "add", "10.98.0.2/24", "dev", "vs0"]);
        _server_ns.exec("ip", &["link", "set", "vs0", "up"]);
        _server_ns.exec("ip", &["link", "set", "lo", "up"]);
        _server_ns.exec("ip", &["route", "add", "10.99.0.0/24", "via", "10.98.0.1"]);

        // The router side: from here on, this thread and its children are
        // inside the router's network namespace.
        assert!(enter(&router), "entering the router namespace");
        run("ip", &["addr", "add", "10.99.0.1/24", "dev", "vr0"]);
        run("ip", &["link", "set", "vr0", "up"]);
        run("ip", &["addr", "add", "10.98.0.1/24", "dev", "vr1"]);
        run("ip", &["link", "set", "vr1", "up"]);
        let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

        let client_mac: crate::mac::MacAddr = _client_ns
            .output("cat", &["/sys/class/net/vc0/address"])
            .parse()
            .expect("client mac");

        // The paywall, exactly as the daemon installs it: no uplink NAT
        // (not needed between two lab networks), no portal.
        let fw = Firewall::system("vr0", None, Ipv4Addr::new(10, 99, 0, 1), 8080, false);
        fw.install().expect("installing the paywall");

        // 1. Unknown device: the kernel drops it.
        assert!(
            !reachable("10.98.0.2"),
            "an unauthorized device must not reach the internet"
        );
        let snapshot = installed_table(&fw);
        assert!(
            snapshot.blocked.is_empty(),
            "no device is known yet, so nothing is attributed"
        );

        // 2. Granted: traffic passes, and the upload counter moves.
        fw.apply_batch(&[SetChange::AddMac(SetName::Allowed, client_mac)])
            .expect("allowing the client");
        assert!(
            reachable("10.98.0.2"),
            "an allowed device must reach the internet"
        );
        let snapshot = installed_table(&fw);
        let allowed = snapshot
            .allowed
            .iter()
            .find(|e| e.mac == client_mac)
            .expect("the device is in the allowed set");
        assert!(allowed.bytes > 0, "uploads are counted: {allowed:?}");

        // 3. The download direction is counted by address, which is how a
        //    client's own traffic is attributed when it is not the sender.
        fw.apply_batch(&[SetChange::AddV4(
            SetName::AllowedV4,
            Ipv4Addr::new(10, 99, 0, 2),
        )])
        .expect("attributing the address");
        assert!(reachable("10.98.0.2"));
        let snapshot = installed_table(&fw);
        let downloads = snapshot
            .allowed_v4
            .iter()
            .find(|e| e.addr == Ipv4Addr::new(10, 99, 0, 2))
            .expect("the address is tracked");
        assert!(downloads.bytes > 0, "downloads are counted: {downloads:?}");

        // 4. Revoked mid-session: the client is back to dropped, and the
        //    drop is attributed to it.
        fw.apply_batch(&[
            SetChange::DelMac(SetName::Allowed, client_mac),
            SetChange::AddMac(SetName::Blocked, client_mac),
        ])
        .expect("revoking the client");
        assert!(
            !reachable("10.98.0.2"),
            "a revoked device must be cut off immediately"
        );
        let snapshot = installed_table(&fw);
        let blocked = snapshot
            .blocked
            .iter()
            .find(|e| e.mac == client_mac)
            .expect("the device is tracked while blocked");
        assert!(blocked.bytes > 0, "blocked drops are attributed");

        // 5. Someone flushes the table by hand: enforcement is gone, and
        //    the reconciler puts it back.
        assert!(run("nft", &["flush", "table", "inet", crate::nft::TABLE]));
        assert!(
            !reachable("10.98.0.2"),
            "a flushed table is an open door: the test needs the client blocked"
        );
        let conn = {
            let dir = std::env::temp_dir().join(format!("piso-netns-{pid}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            crate::store::open(&dir.join("state.db")).unwrap()
        };
        let pass = crate::passes::default_passes()
            .into_iter()
            .find(|p| p.id == "day")
            .unwrap();
        crate::store::grant(&conn, &client_mac, &pass, crate::daemon::now(), "PHP").unwrap();
        let leases = vec![crate::paywall::LeaseAddress {
            mac: client_mac,
            addr: Ipv4Addr::new(10, 99, 0, 2),
        }];
        let outcome = crate::paywall::reconcile(&conn, &fw, crate::daemon::now(), &leases)
            .expect("reconcile");
        assert!(
            outcome.report.reinstalled,
            "a flushed table must read as broken"
        );
        assert!(
            reachable("10.98.0.2"),
            "after the repair, the paying device has internet again"
        );

        // 6. The table is deleted outright: same repair.
        assert!(run("nft", &["delete", "table", "inet", crate::nft::TABLE]));
        let outcome = crate::paywall::reconcile(&conn, &fw, crate::daemon::now(), &leases)
            .expect("reconcile");
        assert!(outcome.report.reinstalled);
        assert!(
            reachable("10.98.0.2"),
            "a deleted table is rebuilt and enforcement restored"
        );

        fw.uninstall().expect("cleaning up the paywall");
    }
}
