//! The panel's transport.
//!
//! The panel is the money side of the hotspot: it grants and revokes
//! access and it shows the login secret. On a shared LAN — and the
//! uplink of a `--dual-radio` hotspot *is* somebody else's network —
//! plain HTTP hands a session cookie to anyone listening, and that
//! cookie is enough to give away internet for free.
//!
//! So the default is HTTPS. The certificate is self-signed, generated
//! once on first start, kept under the config directory, and accepted
//! by each device one time; `admin.tls: "file"` uses a real certificate
//! instead, and `admin.tls: "off"` exists for setups that terminate TLS
//! in front of the panel.
//!
//! The captive portal stays on HTTP, deliberately: browsers only show
//! "sign in to this network" for plain HTTP, and the portal holds nothing
//! worth a certificate.

use std::path::{Path, PathBuf};

use axum_server::tls_rustls::RustlsConfig;

/// Self-signed certificate, kept next to the config.
pub const CERT_FILE: &str = "panel.crt";
/// Its private key. Root-only, like the rest of the state.
pub const KEY_FILE: &str = "panel.key";

fn write_private(path: &Path, contents: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).map_err(|e| format!("writing {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("protecting {}: {e}", path.display()))
}

/// The panel certificate: the operator's own when configured, otherwise
/// a self-signed one, generated on first use and reused after that (a
/// certificate that changed every start would mean a browser warning
/// every start).
pub fn ensure_certificate(
    config_dir: &Path,
    names: &[String],
    configured: Option<(&Path, &Path)>,
) -> Result<(PathBuf, PathBuf), String> {
    if let Some((cert, key)) = configured {
        for path in [cert, key] {
            if !path.exists() {
                return Err(format!("{} does not exist", path.display()));
            }
        }
        return Ok((cert.to_path_buf(), key.to_path_buf()));
    }

    let cert_path = config_dir.join(CERT_FILE);
    let key_path = config_dir.join(KEY_FILE);
    if cert_path.exists() && key_path.exists() {
        return Ok((cert_path, key_path));
    }

    let key = rcgen::KeyPair::generate().map_err(|e| format!("generating the panel key: {e}"))?;
    let mut params = rcgen::CertificateParams::new(names.to_vec())
        .map_err(|e| format!("preparing the panel certificate: {e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "piso-hotspot panel");
    let certificate = params
        .self_signed(&key)
        .map_err(|e| format!("signing the panel certificate: {e}"))?;

    // The key first: a certificate without its key is useless, a key
    // without its certificate is simply regenerated.
    write_private(&key_path, &key.serialize_pem())?;
    write_private(&cert_path, &certificate.pem())?;
    Ok((cert_path, key_path))
}

/// Names the generated certificate is valid for: the addresses the panel
/// is reachable at, so the browser warning is about "not trusted" rather
/// than "wrong host".
pub fn certificate_names(gateway: &str, uplink: Option<&str>, hostname: &str) -> Vec<String> {
    let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    names.push(gateway.to_string());
    if let Some(uplink) = uplink {
        names.push(uplink.to_string());
    }
    if !hostname.is_empty() {
        names.push(hostname.to_string());
        names.push(format!("{hostname}.local"));
    }
    names.sort();
    names.dedup();
    names
}

/// A rustls configuration for the panel.
pub async fn rustls_config(cert: &Path, key: &Path) -> Result<RustlsConfig, String> {
    RustlsConfig::from_pem_file(cert, key)
        .await
        .map_err(|e| format!("reading {}: {e}", cert.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("piso-tls-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_certificate_is_generated_once_and_kept() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("generate");
        let names = certificate_names("10.10.0.1", None, "host");

        let (cert, key) = ensure_certificate(&dir, &names, None).unwrap();
        assert!(cert.exists() && key.exists());
        assert!(
            std::fs::read_to_string(&cert)
                .unwrap()
                .contains("BEGIN CERTIFICATE"),
            "a PEM certificate"
        );
        assert!(
            std::fs::read_to_string(&key)
                .unwrap()
                .contains("PRIVATE KEY"),
            "a PEM private key"
        );
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600,
            "the key is not world-readable"
        );

        // Asking again reuses it: a certificate that changed every start
        // would mean a fresh browser warning every start.
        let second = ensure_certificate(&dir, &names, None).unwrap();
        assert_eq!(second, (cert.clone(), key.clone()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configured_certificates_are_used_and_must_exist() {
        let dir = temp_dir("configured");
        let cert = dir.join("mine.crt");
        let key = dir.join("mine.key");
        std::fs::write(&cert, "cert").unwrap();
        std::fs::write(&key, "key").unwrap();
        assert_eq!(
            ensure_certificate(&dir, &[], Some((&cert, &key))).unwrap(),
            (cert.clone(), key.clone())
        );

        let missing = dir.join("nope.crt");
        let err = ensure_certificate(&dir, &[], Some((&missing, &key))).unwrap_err();
        assert!(err.contains("does not exist"), "{err}");
        // Nothing else was generated behind the operator's back.
        assert!(!dir.join(CERT_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn certificate_names_cover_the_addresses_the_panel_answers_on() {
        let names = certificate_names("10.10.0.1", Some("192.168.1.20"), "piso-box");
        for expected in [
            "localhost",
            "127.0.0.1",
            "10.10.0.1",
            "192.168.1.20",
            "piso-box",
            "piso-box.local",
        ] {
            assert!(names.contains(&expected.to_string()), "missing {expected}");
        }
        // Sorted and deduplicated: rcgen keeps the order it is given.
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names, sorted);
    }
}
