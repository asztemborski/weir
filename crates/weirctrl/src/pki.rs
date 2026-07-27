use anyhow::Result;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::CertificateDer;
use time::{Duration, OffsetDateTime};

const CERT_TTL_BEFORE: Duration = Duration::minutes(5);
const CA_TTL_AFTER: Duration = Duration::days(10 * 365);
const LEAF_TTL_AFTER: Duration = Duration::days(90);

#[derive(Debug)]
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_cert: Certificate,
}

impl CertificateAuthority {
    pub fn generate(mesh_name: &str) -> Result<Self> {
        let key = KeyPair::generate()?;
        let now = OffsetDateTime::now_utc();

        let mut params = CertificateParams::new(vec![mesh_name.to_string()])?;
        params.not_before = now - CERT_TTL_BEFORE;
        params.not_after = now + CA_TTL_AFTER;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];

        let ca_cert = params.self_signed(&key)?;

        Ok(Self {
            issuer: Issuer::new(params, key),
            ca_cert,
        })
    }

    pub fn issue_server_cert(&self, san: &str) -> Result<(CertificateDer<'static>, KeyPair)> {
        let leaf_key = KeyPair::generate()?;
        let now = OffsetDateTime::now_utc();

        let mut params = CertificateParams::new(vec![san.to_string()])?;
        params.is_ca = IsCa::NoCa;
        params.not_before = now - CERT_TTL_BEFORE;
        params.not_after = now + LEAF_TTL_AFTER;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let cert = params.signed_by(&leaf_key, &self.issuer)?;
        Ok((cert.der().clone(), leaf_key))
    }

    #[must_use]
    pub fn ca_cert(&self) -> &Certificate {
        &self.ca_cert
    }
}
