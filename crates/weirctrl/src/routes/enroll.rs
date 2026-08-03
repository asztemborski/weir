use axum::{Json, extract::State};
use rustls_pki_types::{CertificateSigningRequestDer, pem::PemObject};
use serde::Deserialize;

use crate::{app::AppContext, routes::ResponseError};

#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    csr: String,
}

#[axum::debug_handler]
pub async fn enroll_handler(
    State(ctx): State<AppContext>,
    Json(req): Json<EnrollRequest>,
) -> Result<String, ResponseError> {
    let csr_der = CertificateSigningRequestDer::from_pem_slice(req.csr.as_bytes())?;
    let cert = ctx.ca.issue_peer_csr(&csr_der)?;

    Ok(cert.pem())
}
