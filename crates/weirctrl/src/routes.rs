mod enroll;

use anyhow::Error;
use axum::{
    Router,
    response::{Html, IntoResponse, Response},
    routing,
};
use hyper::StatusCode;
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_scalar::Scalar;

use crate::app::AppContext;

const SCALAR_HTML: &str = include_str!("../embeded/scalar.html");

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
    let (router, api) = OpenApiRouter::default()
        .routes(routes!(enroll::enroll_handler))
        .with_state(app_context)
        .split_for_parts();

    let scalar = Scalar::new(api).custom_html(SCALAR_HTML);
    router.route("/docs", routing::get(async move || Html(scalar.to_html())))
}
