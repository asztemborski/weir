use anyhow::Result;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, CertificateSigningRequestDer};
use time::{Duration, OffsetDateTime};

#[derive(Debug, Clone, Copy)]
enum Profile {
    Ca,
    Leaf,
    Peer,
}

impl Profile {
    fn apply(self, params: &mut CertificateParams) {
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + self.ttl();

        match self {
            Self::Ca => {
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            }
            Self::Leaf | Self::Peer => {
                params.is_ca = IsCa::ExplicitNoCa;
                params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![
                    ExtendedKeyUsagePurpose::ClientAuth,
                    ExtendedKeyUsagePurpose::ServerAuth,
                ];
            }
        }
    }

    const fn ttl(self) -> Duration {
        match self {
            Self::Ca => Duration::days(365 * 10),
            Self::Leaf => Duration::days(90),
            Self::Peer => Duration::days(30),
        }
    }
}

#[derive(Debug)]
pub struct CertificateAuthority {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl CertificateAuthority {
    pub fn init(mesh_name: &str) -> Result<Self> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![mesh_name.to_owned()])?;
        Profile::Ca.apply(&mut params);

        Ok(Self {
            issuer: CertifiedIssuer::self_signed(params, key)?,
        })
    }

    pub fn issue_server_cert(&self, san: &str) -> Result<(Certificate, KeyPair)> {
        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![san.to_owned()])?;
        Profile::Leaf.apply(&mut params);

        Ok((params.signed_by(&leaf_key, &self.issuer)?, leaf_key))
    }

    pub fn issue_peer_csr(&self, csr_der: &CertificateSigningRequestDer) -> Result<Certificate> {
        let mut csr = CertificateSigningRequestParams::from_der(csr_der)?;
        Profile::Peer.apply(&mut csr.params);

        Ok(csr.signed_by(&self.issuer)?)
    }

    #[must_use]
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        self.issuer.der()
    }
}
