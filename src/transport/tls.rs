//! TLS/SSL transport support for Oracle connections
//!
//! This module provides TLS support for secure Oracle connections (TCPS protocol).
//! It supports:
//! - Server certificate verification
//! - Client certificates (mutual TLS)
//! - Oracle wallet file parsing
//! - SNI (Server Name Indication)

use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::SecretDocument;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::{Error, Result};

/// TLS configuration for Oracle connections
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Whether to verify server certificates
    pub verify_server: bool,
    /// Server name for SNI (defaults to connection host)
    pub server_name: Option<String>,
    /// Path to CA certificate file (PEM format)
    pub ca_cert_path: Option<String>,
    /// Path to client certificate file (PEM format) for mTLS
    pub client_cert_path: Option<String>,
    /// Path to client private key file (PEM format)
    pub client_key_path: Option<String>,
    /// Oracle wallet directory path
    pub wallet_path: Option<String>,
    /// Wallet password
    pub wallet_password: Option<String>,
    /// Whether to match server DN
    pub ssl_server_dn_match: bool,
    /// Expected server certificate DN
    pub ssl_server_cert_dn: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_server: true,
            server_name: None,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            wallet_path: None,
            wallet_password: None,
            ssl_server_dn_match: false,
            ssl_server_cert_dn: None,
        }
    }
}

impl TlsConfig {
    /// Create a new TLS configuration with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable server certificate verification (NOT recommended for production)
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.verify_server = false;
        self
    }

    /// Set the server name for SNI
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Set the CA certificate path
    pub fn with_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    /// Set client certificate and key paths for mTLS
    pub fn with_client_cert(
        mut self,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
    ) -> Self {
        self.client_cert_path = Some(cert_path.into());
        self.client_key_path = Some(key_path.into());
        self
    }

    /// Set Oracle wallet path
    pub fn with_wallet(mut self, path: impl Into<String>, password: Option<String>) -> Self {
        self.wallet_path = Some(path.into());
        self.wallet_password = password;
        self
    }

    /// Enable server DN matching
    pub fn with_server_dn_match(mut self, expected_dn: Option<String>) -> Self {
        self.ssl_server_dn_match = true;
        self.ssl_server_cert_dn = expected_dn;
        self
    }

    /// Build the rustls ClientConfig from this configuration
    pub fn build_client_config(&self) -> Result<ClientConfig> {
        let mut root_store = RootCertStore::empty();

        // Load root certificates
        if let Some(ca_path) = &self.ca_cert_path {
            // Load custom CA certificate
            let ca_certs = load_certs_from_file(ca_path)?;
            for cert in ca_certs {
                root_store
                    .add(cert)
                    .map_err(|e| Error::Internal(format!("Failed to add CA cert: {}", e)))?;
            }
        } else if let Some(wallet_path) = &self.wallet_path {
            // Try to load from Oracle wallet
            let wallet_certs = load_certs_from_wallet(wallet_path)?;
            for cert in wallet_certs {
                root_store
                    .add(cert)
                    .map_err(|e| Error::Internal(format!("Failed to add wallet cert: {}", e)))?;
            }
        } else {
            // Use system root certificates
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        // Build client config
        let builder = ClientConfig::builder().with_root_certificates(root_store);

        let config = if let (Some(cert_path), Some(key_path)) =
            (&self.client_cert_path, &self.client_key_path)
        {
            // Load client certificate and key for mTLS
            let client_certs = load_certs_from_file(cert_path)?;
            let client_key = load_private_key_from_file(key_path)?;

            builder
                .with_client_auth_cert(client_certs, client_key)
                .map_err(|e| Error::Internal(format!("Failed to configure client auth: {}", e)))?
        } else if let Some(wallet_path) = &self.wallet_path {
            // Try to load client cert from wallet
            let certs_result = load_client_certs_from_wallet(wallet_path);
            let key_result =
                load_private_key_from_wallet(wallet_path, self.wallet_password.as_deref());

            if let (Ok(certs), Ok(Some(key))) = (certs_result, key_result) {
                if !certs.is_empty() {
                    builder.with_client_auth_cert(certs, key).map_err(|e| {
                        Error::Internal(format!("Failed to configure wallet client auth: {}", e))
                    })?
                } else {
                    builder.with_no_client_auth()
                }
            } else {
                builder.with_no_client_auth()
            }
        } else {
            builder.with_no_client_auth()
        };

        Ok(config)
    }
}

/// Wrapper for TLS-secured Oracle connection
pub struct TlsOracleStream {
    inner: TlsStream<TcpStream>,
}

impl TlsOracleStream {
    /// Wrap an existing TLS stream
    pub fn new(stream: TlsStream<TcpStream>) -> Self {
        Self { inner: stream }
    }

    /// Get a reference to the inner TLS stream
    pub fn get_ref(&self) -> &TlsStream<TcpStream> {
        &self.inner
    }

    /// Get a mutable reference to the inner TLS stream
    pub fn get_mut(&mut self) -> &mut TlsStream<TcpStream> {
        &mut self.inner
    }

    /// Consume this wrapper and return the inner stream
    pub fn into_inner(self) -> TlsStream<TcpStream> {
        self.inner
    }
}

impl AsyncRead for TlsOracleStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsOracleStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Connect to an Oracle server using TLS
pub async fn connect_tls(
    tcp_stream: TcpStream,
    server_name: &str,
    config: &TlsConfig,
) -> Result<TlsOracleStream> {
    let client_config = config.build_client_config()?;
    let connector = TlsConnector::from(Arc::new(client_config));

    // Use configured server name or the provided one
    let sni_name = config.server_name.as_deref().unwrap_or(server_name);

    let server_name = ServerName::try_from(sni_name.to_string())
        .map_err(|_| Error::Internal(format!("Invalid server name for TLS: {}", sni_name)))?;

    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    Ok(TlsOracleStream::new(tls_stream))
}

/// Load certificates from a PEM file
fn load_certs_from_file(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .map_err(|e| Error::Internal(format!("Failed to open cert file {}: {}", path, e)))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        return Err(Error::Internal(format!(
            "No certificates found in {}",
            path
        )));
    }

    Ok(certs)
}

/// Load private key from a PEM file
fn load_private_key_from_file(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .map_err(|e| Error::Internal(format!("Failed to open key file {}: {}", path, e)))?;
    let mut reader = BufReader::new(file);

    read_private_key(&mut reader)
        .map_err(|e| Error::Internal(format!("Failed to parse key file {}: {}", path, e)))?
        .ok_or_else(|| Error::Internal(format!("No private key found in {}", path)))
}

/// Reads the first private key (PKCS#1, PKCS#8 or SEC1) from PEM input.
/// `Ok(None)` when the input holds no key, so callers can tell "missing" from
/// "malformed".
fn read_private_key(
    reader: &mut dyn std::io::BufRead,
) -> std::result::Result<Option<PrivateKeyDer<'static>>, pem::Error> {
    match PrivateKeyDer::from_pem_reader(reader) {
        Ok(key) => Ok(Some(key)),
        Err(pem::Error::NoItemsFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Load certificates from an Oracle wallet directory
fn load_certs_from_wallet(wallet_path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let path = Path::new(wallet_path);

    // Try ewallet.pem first (thin client format)
    let pem_path = path.join("ewallet.pem");
    if pem_path.exists() {
        return load_certs_from_file(pem_path.to_str().unwrap());
    }

    // Try cwallet.sso (auto-login wallet)
    let sso_path = path.join("cwallet.sso");
    if sso_path.exists() {
        // SSO wallets are auto-login, we just need to load the certs
        // This is a simplified implementation - real SSO parsing is more complex
        return Err(Error::FeatureNotSupported(
            "Auto-login wallet (cwallet.sso) parsing not yet implemented".to_string(),
        ));
    }

    Err(Error::Internal(format!(
        "No wallet file found in {}",
        wallet_path
    )))
}

/// Load client certificates from an Oracle wallet
fn load_client_certs_from_wallet(wallet_path: &str) -> Result<Vec<CertificateDer<'static>>> {
    // In Oracle wallets, client certs are also in ewallet.pem
    load_certs_from_wallet(wallet_path)
}

/// Load private key from an Oracle wallet
///
/// Oracle wallet PEM files (ewallet.pem) typically contain encrypted private keys.
/// The wallet_password is used to decrypt the key if it's encrypted.
fn load_private_key_from_wallet(
    wallet_path: &str,
    wallet_password: Option<&str>,
) -> Result<Option<PrivateKeyDer<'static>>> {
    let path = Path::new(wallet_path);
    let pem_path = path.join("ewallet.pem");

    if !pem_path.exists() {
        return Ok(None);
    }

    // Read the file contents to check for encrypted keys
    let pem_contents = fs::read_to_string(&pem_path)
        .map_err(|e| Error::Internal(format!("Failed to read wallet file: {}", e)))?;

    // Check if the file contains an encrypted private key (PKCS#8 encrypted format)
    if pem_contents.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        // Need password to decrypt
        let password = wallet_password.ok_or_else(|| {
            Error::Internal(
                "Wallet contains encrypted private key but no password provided".to_string(),
            )
        })?;

        // Parse PEM to get DER bytes using SecretDocument
        let (label, secret_doc) = SecretDocument::from_pem(&pem_contents)
            .map_err(|e| Error::Internal(format!("Failed to parse encrypted PEM: {}", e)))?;

        // Verify it's an encrypted private key
        if label != "ENCRYPTED PRIVATE KEY" {
            return Err(Error::Internal(format!(
                "Expected ENCRYPTED PRIVATE KEY, got: {}",
                label
            )));
        }

        // Decode the EncryptedPrivateKeyInfo from DER bytes
        let encrypted_key = EncryptedPrivateKeyInfo::try_from(secret_doc.as_bytes())
            .map_err(|e| Error::Internal(format!("Failed to decode encrypted key: {}", e)))?;

        // Decrypt the key
        let decrypted_doc = encrypted_key
            .decrypt(password.as_bytes())
            .map_err(|e| Error::Internal(format!("Failed to decrypt wallet private key: {}", e)))?;

        // Convert to DER format that rustls expects
        let der_bytes = decrypted_doc.as_bytes().to_vec();
        Ok(Some(PrivateKeyDer::Pkcs8(der_bytes.into())))
    } else {
        // Try an unencrypted key with the standard PEM reader
        let file = File::open(&pem_path)
            .map_err(|e| Error::Internal(format!("Failed to open wallet: {}", e)))?;
        let mut reader = BufReader::new(file);

        read_private_key(&mut reader)
            .map_err(|e| Error::Internal(format!("Failed to parse wallet key: {}", e)))
    }
}

/// Protocol type for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    /// Plain TCP connection
    #[default]
    Tcp,
    /// TLS-secured connection (TCPS)
    Tcps,
}

impl Protocol {
    /// Check if this protocol uses TLS
    pub fn is_secure(&self) -> bool {
        matches!(self, Protocol::Tcps)
    }

    /// Get the protocol string for connection descriptors
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Tcps => "tcps",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "tcps" | "ssl" | "tls" => Ok(Protocol::Tcps),
            _ => Err(Error::InvalidConnectionString(format!(
                "Unknown protocol: {}",
                s
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert!(config.verify_server);
        assert!(config.server_name.is_none());
        assert!(config.ca_cert_path.is_none());
    }

    #[test]
    fn test_tls_config_builder() {
        let config = TlsConfig::new()
            .with_server_name("oracle.example.com")
            .with_ca_cert("/path/to/ca.pem")
            .with_client_cert("/path/to/client.pem", "/path/to/client.key")
            .with_server_dn_match(Some("CN=oracle".to_string()));

        assert_eq!(config.server_name, Some("oracle.example.com".to_string()));
        assert_eq!(config.ca_cert_path, Some("/path/to/ca.pem".to_string()));
        assert_eq!(
            config.client_cert_path,
            Some("/path/to/client.pem".to_string())
        );
        assert_eq!(
            config.client_key_path,
            Some("/path/to/client.key".to_string())
        );
        assert!(config.ssl_server_dn_match);
    }

    #[test]
    fn test_tls_config_wallet() {
        let config =
            TlsConfig::new().with_wallet("/opt/oracle/wallet", Some("password".to_string()));

        assert_eq!(config.wallet_path, Some("/opt/oracle/wallet".to_string()));
        assert_eq!(config.wallet_password, Some("password".to_string()));
    }

    #[test]
    fn test_protocol_from_str() {
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("TCP".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("tcps".parse::<Protocol>().unwrap(), Protocol::Tcps);
        assert_eq!("TCPS".parse::<Protocol>().unwrap(), Protocol::Tcps);
        assert_eq!("ssl".parse::<Protocol>().unwrap(), Protocol::Tcps);
        assert_eq!("tls".parse::<Protocol>().unwrap(), Protocol::Tcps);
    }

    #[test]
    fn test_protocol_is_secure() {
        assert!(!Protocol::Tcp.is_secure());
        assert!(Protocol::Tcps.is_secure());
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Tcps.to_string(), "tcps");
    }

    #[test]
    fn test_danger_accept_invalid_certs() {
        let config = TlsConfig::new().danger_accept_invalid_certs();
        assert!(!config.verify_server);
    }

    // A throwaway self-signed P-256 certificate and its PKCS#8 key, used only
    // to exercise PEM loading. Not a secret: it protects nothing.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBaDCCAQ6gAwIBAgIUAVXpikMbO0keIizrb86wMmhr3O4wCgYIKoZIzj0EAwIw
GTEXMBUGA1UEAwwOb3JhY2xlLXJzLXRlc3QwIBcNMjYxMTEzMTIzMjE4WhgPMjEy
NjEwMjAxMjMyMThaMBkxFzAVBgNVBAMMDm9yYWNsZS1ycy10ZXN0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEGHV55GSO5WsSrrHxsGluoVTB+f2g3CidhPiBfvD/
27CIqB1FotKDLBuwGAR82ogv9u9vskc2CF26H/DDx9lkoaMyMDAwHQYDVR0OBBYE
FFUviwDGsWSjhLBZqbjTKbJ3NTiOMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0E
AwIDSAAwRQIhAPBOZUn02i1Ds3Qk+tmBoylA0lSbjAE1yG74t32dYSkZAiAyiK2+
+FyQAI71v3fYX5iD+BOG273OagiRv6BsPe2ERQ==
-----END CERTIFICATE-----
";
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjABLjxKw2n+FWXPh
jbtvgIcN7duTF0QWFryODEb08EGhRANCAAQYdXnkZI7laxKusfGwaW6hVMH5/aDc
KJ2E+IF+8P/bsIioHUWi0oMsG7AYBHzaiC/272+yRzYIXbof8MPH2WSh
-----END PRIVATE KEY-----
";

    /// Writes `contents` to a fresh file in the temp dir and returns its path.
    fn temp_pem(name: &str, contents: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("oracle-rs-tls-{}-{}.pem", std::process::id(), name));
        fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn test_load_certs_from_pem_file() {
        let path = temp_pem("certs", TEST_CERT_PEM);
        let certs = load_certs_from_file(&path).unwrap();
        assert_eq!(certs.len(), 1);
        // Skips the key block in a combined file, as before.
        let combined = temp_pem("combined", &format!("{TEST_KEY_PEM}{TEST_CERT_PEM}"));
        assert_eq!(load_certs_from_file(&combined).unwrap().len(), 1);
    }

    #[test]
    fn test_load_certs_rejects_file_without_certs() {
        let path = temp_pem("no-certs", TEST_KEY_PEM);
        let error = load_certs_from_file(&path).unwrap_err().to_string();
        assert!(error.contains("No certificates found"), "{error}");
    }

    #[test]
    fn test_load_private_key_from_pem_file() {
        let path = temp_pem("key", TEST_KEY_PEM);
        let key = load_private_key_from_file(&path).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn test_load_private_key_rejects_file_without_key() {
        let path = temp_pem("no-key", TEST_CERT_PEM);
        let error = load_private_key_from_file(&path).unwrap_err().to_string();
        assert!(error.contains("No private key found"), "{error}");
    }

    #[test]
    fn test_unencrypted_wallet_key_is_optional() {
        let dir = std::env::temp_dir().join(format!("oracle-rs-wallet-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let wallet = dir.to_str().unwrap();

        fs::write(dir.join("ewallet.pem"), TEST_CERT_PEM).unwrap();
        assert!(load_private_key_from_wallet(wallet, None)
            .unwrap()
            .is_none());

        fs::write(
            dir.join("ewallet.pem"),
            format!("{TEST_CERT_PEM}{TEST_KEY_PEM}"),
        )
        .unwrap();
        let key = load_private_key_from_wallet(wallet, None).unwrap();
        assert!(matches!(key, Some(PrivateKeyDer::Pkcs8(_))));
    }
}
