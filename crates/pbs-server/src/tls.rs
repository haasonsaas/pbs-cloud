//! TLS/HTTPS support using rustls
//!
//! Provides TLS termination for secure connections.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to certificate file (PEM format)
    pub cert_path: Option<String>,
    /// Path to private key file (PEM format)
    pub key_path: Option<String>,
    /// Whether to generate self-signed cert if none provided
    pub generate_self_signed: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            generate_self_signed: true,
        }
    }
}

impl TlsConfig {
    /// Create TLS config with certificate paths
    pub fn with_certs(cert_path: &str, key_path: &str) -> Self {
        Self {
            cert_path: Some(cert_path.to_string()),
            key_path: Some(key_path.to_string()),
            generate_self_signed: false,
        }
    }

    /// Create TLS config that generates self-signed certs
    pub fn self_signed() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            generate_self_signed: true,
        }
    }

    /// Disable TLS (for development)
    pub fn disabled() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            generate_self_signed: false,
        }
    }

    /// Check if TLS is enabled
    pub fn is_enabled(&self) -> bool {
        self.cert_path.is_some() || self.generate_self_signed
    }
}

/// Load certificates from PEM file
fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// Load private key from PEM file
fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Try to read PKCS8 key first
    let keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;

    if let Some(key) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    // Try RSA key
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;

    if let Some(key) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    // Try EC key
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let keys: Vec<_> = rustls_pemfile::ec_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;

    if let Some(key) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    anyhow::bail!("No valid private key found in {}", path.display())
}

/// Generate a self-signed certificate
fn generate_self_signed_cert() -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    info!("Generating self-signed certificate...");

    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];

    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("Failed to parse private key: {:?}", e))?;

    warn!("Using self-signed certificate - not suitable for production!");
    info!("Certificate fingerprint: {}", hex::encode(&cert.der()[..20]));

    Ok((vec![cert_der], key_der))
}

/// Create a TLS acceptor from configuration
pub fn create_tls_acceptor(config: &TlsConfig) -> anyhow::Result<Option<TlsAcceptor>> {
    if !config.is_enabled() {
        info!("TLS disabled - running in insecure mode");
        return Ok(None);
    }

    let (certs, key) = if let (Some(cert_path), Some(key_path)) = (&config.cert_path, &config.key_path) {
        info!("Loading TLS certificate from {}", cert_path);
        let certs = load_certs(Path::new(cert_path))?;
        let key = load_private_key(Path::new(key_path))?;
        (certs, key)
    } else if config.generate_self_signed {
        generate_self_signed_cert()?
    } else {
        anyhow::bail!("TLS enabled but no certificates configured");
    };

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    info!("TLS acceptor initialized");
    Ok(Some(acceptor))
}

/// Save generated certificate to files (for debugging/inspection)
pub async fn save_self_signed_cert(
    data_dir: &Path,
) -> anyhow::Result<(String, String)> {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tokio::fs;

    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];

    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)?;

    let cert_path = data_dir.join("server.crt");
    let key_path = data_dir.join("server.key");

    fs::write(&cert_path, cert.pem()).await?;
    fs::write(&key_path, key_pair.serialize_pem()).await?;

    // Set restrictive permissions on key file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_path, perms)?;
    }

    info!("Saved self-signed certificate to {:?}", cert_path);
    info!("Saved private key to {:?}", key_path);

    Ok((
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_self_signed() {
        let (certs, _key) = generate_self_signed_cert().unwrap();
        assert!(!certs.is_empty());
    }

    #[tokio::test]
    async fn test_save_self_signed() {
        let temp_dir = TempDir::new().unwrap();
        let (cert_path, key_path) = save_self_signed_cert(temp_dir.path()).await.unwrap();

        assert!(Path::new(&cert_path).exists());
        assert!(Path::new(&key_path).exists());
    }

    #[test]
    fn test_create_acceptor_self_signed() {
        let config = TlsConfig::self_signed();
        let acceptor = create_tls_acceptor(&config).unwrap();
        assert!(acceptor.is_some());
    }

    #[test]
    fn test_create_acceptor_disabled() {
        let config = TlsConfig::disabled();
        let acceptor = create_tls_acceptor(&config).unwrap();
        assert!(acceptor.is_none());
    }
}
