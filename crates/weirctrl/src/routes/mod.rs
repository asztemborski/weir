mod enroll;

use anyhow::Error;
use axum::response::{IntoResponse, Response};
pub use enroll::*;
use hyper::StatusCode;

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
