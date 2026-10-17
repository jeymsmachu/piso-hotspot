//! Config file generation for hostapd and dnsmasq.
//!
//! Both run as supervised children of the daemon with configs written
//! under `/run/piso-hotspot/` — nothing here touches the system's own
//! hostapd/dnsmasq configuration.

use std::net::Ipv4Addr;

use crate::config::Config;

pub const HOSTAPD_CONF: &str = "/run/piso-hotspot/hostapd.conf";
pub const DNSMASQ_CONF: &str = "/run/piso-hotspot/dnsmasq.conf";
pub const LEASE_FILE: &str = "/run/piso-hotspot/dnsmasq.leases";

/// hostapd configuration for the given interface.
///
/// Channel 1–14 is 2.4 GHz (`hw_mode=g`); anything above is 5/6 GHz
/// (`hw_mode=a`).
pub fn hostapd_config(cfg: &Config, iface: &str) -> String {
    let mut out = format!(
        "interface={iface}\ndriver=nl80211\nssid={ssid}\nchannel={channel}\n",
        ssid = cfg.ap.ssid,
        channel = cfg.ap.channel,
    );
    out.push_str(if cfg.ap.channel <= 14 {
        "hw_mode=g\n"
    } else {
        "hw_mode=a\n"
    });
    if let Some(country) = cfg.ap.country_code.as_deref() {
        out.push_str(&format!("country_code={country}\n"));
    }
    if cfg.ap.ieee80211n {
        out.push_str("ieee80211n=1\nwmm_enabled=1\n");
    }
    if cfg.ap.isolate_clients {
        out.push_str("ap_isolate=1\n");
    }
    out.push_str(&format!("max_num_sta={}\n", cfg.ap.max_clients));

    if cfg.ap.passphrase.is_empty() {
        // Open network: the paywall, not the radio password, is the gate.
        out.push_str("auth_algs=1\n");
    } else {
        out.push_str(&format!(
            "auth_algs=1\n\
             wpa=2\n\
             wpa_passphrase={pass}\n\
             wpa_key_mgmt=WPA-PSK\n\
             rsn_pairwise=CCMP\n",
            pass = cfg.ap.passphrase,
        ));
    }
    // The daemon runs with a closed lid on battery; keep the log quiet.
    out.push_str("logger_syslog_level=2\n");
    out
}

/// dnsmasq configuration: DHCP + DNS for the client subnet only.
pub fn dnsmasq_config(cfg: &Config, iface: &str) -> String {
    let octets = cfg.gateway.octets();
    format!(
        "conf-file=/dev/null\n\
         interface={iface}\n\
         bind-interfaces\n\
         dhcp-range={first},{last},255.255.255.0,1h\n\
         dhcp-leasefile={leases}\n\
         server=1.1.1.1\n\
         server=8.8.8.8\n\
         domain-needed\n\
         bogus-priv\n",
        first = Ipv4Addr::new(octets[0], octets[1], octets[2], 10),
        last = Ipv4Addr::new(octets[0], octets[1], octets[2], 254),
        leases = LEASE_FILE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg() -> Config {
        Config::default()
    }

    #[test]
    fn hostapd_open_network_by_default() {
        let out = hostapd_config(&cfg(), "wlan0");
        assert!(out.contains("interface=wlan0"));
        assert!(out.contains("ssid=piso-hotspot"));
        assert!(out.contains("channel=6"));
        assert!(out.contains("hw_mode=g"));
        assert!(!out.contains("wpa=2"));
        assert!(!out.contains("wpa_passphrase"));
    }

    #[test]
    fn hostapd_wpa2_when_passphrase_set() {
        let mut c = cfg();
        c.ap.passphrase = "printed-on-a-sign".to_string();
        let out = hostapd_config(&c, "wlan0");
        assert!(out.contains("wpa=2"));
        assert!(out.contains("wpa_passphrase=printed-on-a-sign"));
        assert!(out.contains("rsn_pairwise=CCMP"));
    }

    #[test]
    fn hostapd_band_follows_channel() {
        let mut c = cfg();
        c.ap.channel = 1;
        assert!(hostapd_config(&c, "wlan0").contains("hw_mode=g"));
        c.ap.channel = 14;
        assert!(hostapd_config(&c, "wlan0").contains("hw_mode=g"));
        c.ap.channel = 36;
        assert!(hostapd_config(&c, "wlan0").contains("hw_mode=a"));
        c.ap.channel = 149;
        let out = hostapd_config(&c, "wlan0");
        assert!(out.contains("hw_mode=a"));
        assert!(out.contains("channel=149"));
    }

    #[test]
    fn hostapd_honours_settings() {
        let mut c = cfg();
        c.ap.ssid = "School-WiFi".into();
        c.ap.max_clients = 8;
        c.ap.isolate_clients = true;
        c.ap.ieee80211n = false;
        c.ap.country_code = Some("PH".into());
        let out = hostapd_config(&c, "wlan0");
        assert!(out.contains("ssid=School-WiFi"));
        assert!(out.contains("max_num_sta=8"));
        assert!(out.contains("ap_isolate=1"));
        assert!(!out.contains("ieee80211n"));
        assert!(out.contains("country_code=PH"));
    }

    #[test]
    fn country_omitted_when_unset() {
        let c = cfg();
        assert!(!hostapd_config(&c, "wlan0").contains("country_code"));
    }

    #[test]
    fn dnsmasq_range_derives_from_gateway() {
        let mut c = cfg();
        c.gateway = Ipv4Addr::new(10, 10, 0, 1);
        let out = dnsmasq_config(&c, "wlan0");
        assert!(out.contains("dhcp-range=10.10.0.10,10.10.0.254,255.255.255.0,1h"));
        assert!(out.contains(&format!("dhcp-leasefile={LEASE_FILE}")));
        assert!(out.contains("interface=wlan0"));
        assert!(out.contains("bind-interfaces"));

        c.gateway = Ipv4Addr::new(192, 168, 50, 1);
        let out = dnsmasq_config(&c, "ap0");
        assert!(out.contains("dhcp-range=192.168.50.10,192.168.50.254"));
        assert!(out.contains("interface=ap0"));
    }

    #[test]
    fn dnsmasq_ignores_system_config() {
        let out = dnsmasq_config(&cfg(), "wlan0");
        assert!(out.starts_with("conf-file=/dev/null"));
        assert!(out.contains("server=1.1.1.1"));
    }
}
