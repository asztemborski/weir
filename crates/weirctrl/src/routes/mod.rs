mod enroll;

use anyhow::Error;
use axum::{
    Router,
    response::{IntoResponse, Response},
};
use hyper::StatusCode;
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_scalar::{Scalar, Servable};

use crate::app::AppContext;

pub struct ResponseError(Error);

impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl<E: Into<Error>> From<E> for ResponseError {
    fn from(value: E) -> Self {
        Self(value.into())
    }
}

pub fn build_router(app_context: AppContext) -> Router {
    let (router, api) = OpenApiRouter::new()
        .routes(routes!(enroll::enroll_handler))
        .with_state(app_context)
        .split_for_parts();

    router.merge(Scalar::with_url("/docs", api))
}
