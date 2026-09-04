use std::path::Path;

use anyhow::Result;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, CertificateSigningRequestDer, pem::PemObject};
use time::{Duration, OffsetDateTime};
use tokio::fs;

const CLOCK_SKEW: Duration = Duration::hours(1);

const END_ENTITY_EKU: &[ExtendedKeyUsagePurpose] = &[
    ExtendedKeyUsagePurpose::ClientAuth,
    ExtendedKeyUsagePurpose::ServerAuth,
];

#[derive(Debug, Clone)]
struct Profile {
    ttl: Duration,
    is_ca: IsCa,
    key_usages: &'static [KeyUsagePurpose],
    extended_key_usages: &'static [ExtendedKeyUsagePurpose],
}

impl Profile {
    const CA: Self = Self {
        ttl: Duration::days(365 * 10),
        is_ca: IsCa::Ca(BasicConstraints::Unconstrained),
        key_usages: &[KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        extended_key_usages: &[],
    };

    const LEAF: Self = Self {
        ttl: Duration::days(90),
        ..Self::END_ENTITY
    };

    const PEER: Self = Self {
        ttl: Duration::days(30),
        ..Self::END_ENTITY
    };

    const END_ENTITY: Self = Self {
        ttl: Duration::ZERO,
        is_ca: IsCa::ExplicitNoCa,
        key_usages: &[KeyUsagePurpose::DigitalSignature],
        extended_key_usages: END_ENTITY_EKU,
    };

    fn apply(&self, params: &mut CertificateParams) {
        let now = OffsetDateTime::now_utc();
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + self.ttl;
        params.is_ca = self.is_ca;
        params.key_usages = self.key_usages.to_vec();
        params.extended_key_usages = self.extended_key_usages.to_vec();
    }

    fn params(&self, sans: Vec<String>) -> Result<CertificateParams> {
        let mut params = CertificateParams::new(sans)?;
        self.apply(&mut params);
        Ok(params)
    }
}

#[derive(Debug)]
pub struct CertificateAuthority {
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl CertificateAuthority {
    pub async fn init(cert_dir: &Path, san: &str) -> Result<Self> {
        let cert_path = cert_dir.join("ca.pem");
        let key_path = cert_dir.join("ca_key.pem");

        if let Ok(ca) = Self::load(&cert_path, &key_path).await {
            return Ok(ca);
        }

        Self::generate_and_save(&cert_path, &key_path, san).await
    }

    pub fn issue_server_cert(&self, san: &str) -> Result<(Certificate, KeyPair)> {
        let key = KeyPair::generate()?;
        let params = Profile::LEAF.params(vec![san.to_string()])?;
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok((cert, key))
    }

    pub fn issue_peer_csr(&self, csr_der: &CertificateSigningRequestDer) -> Result<Certificate> {
        let mut csr = CertificateSigningRequestParams::from_der(csr_der)?;
        Profile::PEER.apply(&mut csr.params);
        csr.signed_by(&self.issuer).map_err(Into::into)
    }

    async fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let (cert_pem, key_pem) =
            tokio::try_join!(fs::read_to_string(cert_path), fs::read_to_string(key_path))?;

        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes())?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, KeyPair::from_pem(&key_pem)?)?;

        Ok(Self { der, issuer })
    }

    async fn generate_and_save(cert_path: &Path, key_path: &Path, san: &str) -> Result<Self> {
        let params = Profile::CA.params(vec![san.to_string()])?;
        let key_pair = KeyPair::generate()?;
        let certificate = params.self_signed(&key_pair)?;

        tokio::try_join!(
            fs::write(cert_path, certificate.pem()),
            fs::write(key_path, key_pair.serialize_pem())
        )?;

        Ok(Self {
            der: certificate.der().clone(),
            issuer: Issuer::new(params, key_pair),
        })
    }

    #[must_use]
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.der
    }
}
