use axum::{Json, extract::State};
use rustls_pki_types::{CertificateSigningRequestDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{app::AppContext, routes::ResponseError};

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct EnrollRequest {
    csr: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(super) struct EnrollResponse {
    pem: String,
}

#[utoipa::path(get, path = "/enroll", responses((status = OK, body = EnrollResponse)))]
pub(super) async fn enroll_handler(
    State(ctx): State<AppContext>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ResponseError> {
    let csr_der = CertificateSigningRequestDer::from_pem_slice(req.csr.as_bytes())?;
    let cert = ctx.ca.issue_peer_csr(&csr_der)?;

    let response = EnrollResponse { pem: cert.pem() };
    Ok(Json(response))
}
