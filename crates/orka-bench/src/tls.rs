//! A throwaway certificate authority and server certificate for TLS
//! tests.
//!
//! A test that must exercise a client's TLS trust logic (for example,
//! `ORKA_EXTRA_CA_FILE`) needs a certificate authority it controls,
//! since it cannot use a certificate signed by a real public CA for a
//! loopback address. [`ServerTls::generate`] builds one CA and one
//! leaf certificate signed by it, entirely in memory.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, SanType};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tempfile::NamedTempFile;

/// A self-signed CA and one leaf certificate it issued, ready to back
/// a [`crate::fake_http::Server::start_tls`] and to hand a trusting
/// client's CA bundle.
pub struct ServerTls {
    /// The CA certificate, PEM-encoded. A test's TLS client trusts
    /// this (and only this) so a fake server's certificate verifies
    /// without touching the system's real trust store.
    pub ca_pem: String,
    /// The leaf certificate, PEM-encoded.
    pub cert_pem: String,
    /// The leaf certificate's private key, PEM-encoded.
    pub key_pem: String,
    /// Backing storage for [`ServerTls::ca_file_path`]. Kept alive for
    /// as long as `ServerTls` is, since the temp file is deleted when
    /// this handle drops.
    ca_file: NamedTempFile,
}

impl ServerTls {
    /// Generates a new CA and a leaf certificate signed by it. The
    /// leaf carries Subject Alternative Names for `localhost`,
    /// `127.0.0.1`, and `::1`, covering every way a test's client
    /// might name the loopback server.
    pub fn generate() -> Result<ServerTls, String> {
        let ca_key = KeyPair::generate().map_err(|e| format!("cannot generate a CA key: {e}"))?;
        let mut ca_params = CertificateParams::new(Vec::new())
            .map_err(|e| format!("cannot build CA certificate parameters: {e}"))?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut ca_name = DistinguishedName::new();
        ca_name.push(DnType::CommonName, "orka-bench test CA");
        ca_params.distinguished_name = ca_name;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| format!("cannot self-sign the CA certificate: {e}"))?;

        let leaf_key =
            KeyPair::generate().map_err(|e| format!("cannot generate a leaf key: {e}"))?;
        let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()])
            .map_err(|e| format!("cannot build leaf certificate parameters: {e}"))?;
        leaf_params.subject_alt_names = vec![
            SanType::DnsName(
                "localhost"
                    .try_into()
                    .map_err(|e| format!("invalid DNS SAN: {e}"))?,
            ),
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ];
        let mut leaf_name = DistinguishedName::new();
        leaf_name.push(DnType::CommonName, "localhost");
        leaf_params.distinguished_name = leaf_name;
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| format!("cannot sign the leaf certificate: {e}"))?;

        // rcgen's own PEM encoding lives behind its "pem" feature,
        // which pulls in the `pem` crate and, with it, a second
        // `base64` major version alongside the one this crate already
        // uses elsewhere. Encoding DER to PEM by hand with the
        // `base64` dependency already on hand avoids that duplicate.
        let ca_pem = der_to_pem("CERTIFICATE", ca_cert.der());
        let cert_pem = der_to_pem("CERTIFICATE", leaf_cert.der());
        let key_pem = der_to_pem("PRIVATE KEY", &leaf_key.serialize_der());

        let mut ca_file = NamedTempFile::new()
            .map_err(|e| format!("cannot create a temp file for the CA certificate: {e}"))?;
        ca_file
            .write_all(ca_pem.as_bytes())
            .map_err(|e| format!("cannot write the CA certificate to a temp file: {e}"))?;
        ca_file
            .flush()
            .map_err(|e| format!("cannot flush the CA certificate temp file: {e}"))?;

        Ok(ServerTls {
            ca_pem,
            cert_pem,
            key_pem,
            ca_file,
        })
    }

    /// The path to a temp file holding [`ServerTls::ca_pem`], ready to
    /// hand to a client (for example as `ORKA_EXTRA_CA_FILE`) that
    /// reads its extra trust roots from a file rather than a string.
    pub fn ca_file_path(&self) -> &Path {
        self.ca_file.path()
    }

    /// Builds a rustls server config carrying the leaf certificate and
    /// key, ready for [`crate::fake_http::Server::start_tls`]. Kept as
    /// its own method (rather than inline in that call) so another
    /// fake server built later can reuse the same certificate.
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        let certs = parse_cert_chain(&self.cert_pem);
        let key = parse_private_key(&self.key_pem);
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            // The certificate and key just came out of this same
            // struct, both freshly generated; a mismatch here is a
            // bug in this module, not a condition a caller can act on.
            .expect("generated certificate and key must be a valid server config");
        Arc::new(config)
    }
}

/// Encodes DER bytes as a PEM block (RFC 7468): standard base64,
/// wrapped at 64 characters per line, between `BEGIN`/`END label`
/// lines. `KeyPair::serialize_der` returns a PKCS8 key, so `"PRIVATE
/// KEY"` (not `"RSA PRIVATE KEY"`, the PKCS1 label) is the correct
/// header for a key.
fn der_to_pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 output is ASCII"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// Parses one PEM certificate chain into DER form. Panics on a
/// malformed PEM string: the only input this module ever feeds it is
/// PEM this same module just generated.
fn parse_cert_chain(cert_pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("generated certificate PEM must parse")
}

/// Parses one PEM private key into DER form. Panics on a malformed PEM
/// string, for the same reason as [`parse_cert_chain`].
fn parse_private_key(key_pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .expect("generated key PEM must parse")
        .expect("generated key PEM must contain a private key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_http::{Request, Response, Server};
    use std::sync::Arc as StdArc;

    #[test]
    fn a_client_trusting_the_ca_connects_successfully() {
        let tls = ServerTls::generate().unwrap();
        let server = Server::start_tls(&tls, StdArc::new(|_req: &Request| Response::text(200, "ok")));

        let mut root_certs = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut tls.ca_pem.as_bytes()) {
            root_certs.add(cert.unwrap()).unwrap();
        }
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        let agent = ureq::AgentBuilder::new().tls_config(Arc::new(tls_config)).build();

        let body = agent.get(&server.base_url()).call().unwrap().into_string().unwrap();
        assert_eq!(body, "ok");
    }

    #[test]
    fn a_client_without_the_ca_is_rejected() {
        let tls = ServerTls::generate().unwrap();
        let server = Server::start_tls(&tls, StdArc::new(|_req: &Request| Response::text(200, "ok")));

        // The default agent trusts only public roots, none of which
        // signed this test's throwaway CA.
        let agent = ureq::AgentBuilder::new().build();
        let result = agent.get(&server.base_url()).call();
        assert!(result.is_err(), "a client with no matching trust root must fail the handshake");
    }
}
