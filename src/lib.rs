//! A library to secure [GitHub Webhooks][github-webhooks] and extract JSON
//! event payloads in [Axum][axum].
//!
//! The library is an [Extractor][axum-extractor] paired with
//! [State][axum-state] to provide the required [Secret
//! Token][github-secret-token].
//!
//! Usage looks like:
//! ```
//! # use axum::response::IntoResponse;
//! # use axum::routing::post;
//! # use axum::Router;
//! # use serde::Deserialize;
//! # use std::sync::Arc;
//! use axum_github_webhook_extract::{GithubToken, GithubEvent};
//!
//! #[derive(Debug, Deserialize)]
//! struct Event {
//!     action: String,
//! }
//!
//! async fn echo(GithubEvent(e): GithubEvent<Event>) -> impl IntoResponse {
//!     e.action
//! }
//!
//! fn app() -> Router {
//!     let token = String::from("d4705034dd0777ee9e1e3078a12a06985151b76f");
//!     Router::new()
//!         .route("/", post(echo))
//!         .with_state(GithubToken(Arc::new(token)))
//! }
//! ```
//!
//! You will usually get the token from your environment or configuration.
//! The event payload is under your control, just make sure to configure it to
//! use [JSON][github-json].
//!
//! [github-webhooks]: https://docs.github.com/en/webhooks-and-events/webhooks/securing-your-webhooks
//! [axum]: https://docs.rs/axum/latest/axum/
//! [axum-extractor]: https://docs.rs/axum/latest/axum/#extractors
//! [axum-state]: https://docs.rs/axum/latest/axum/#sharing-state-with-handlers
//! [github-secret-token]: https://docs.github.com/en/webhooks-and-events/webhooks/securing-your-webhooks#setting-your-secret-token
//! [github-json]: https://docs.github.com/en/webhooks-and-events/webhooks/creating-webhooks#content-type

use axum::async_trait;
use axum::body::Bytes;
use axum::extract::{FromRef, FromRequest, Request};
use axum::http::StatusCode;
use hmac_sha256::HMAC;
use serde::de::DeserializeOwned;
use std::fmt::Display;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// State to provide the Github Token to verify Event signature.
#[derive(Debug, Clone)]
pub struct GithubToken(pub Arc<String>);

/// Verify and extract Github Event Payload.
#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct GithubEvent<T>(pub T);

fn err(m: impl Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, m.to_string())
}

#[async_trait]
impl<T, S> FromRequest<S> for GithubEvent<T>
where
    GithubToken: FromRef<S>,
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let token = GithubToken::from_ref(state);
        let signature_sha256 = req
            .headers()
            .get("X-Hub-Signature-256")
            .and_then(|v| v.to_str().ok())
            .ok_or(err("signature missing"))?
            .strip_prefix("sha256=")
            .ok_or(err("signature prefix missing"))?;
        let signature = hex::decode(signature_sha256).map_err(|_| err("signature malformed"))?;
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|_| err("error reading body"))?;
        let mac = HMAC::mac(&body, token.0.as_bytes());
        if mac.ct_ne(&signature).into() {
            return Err(err("signature mismatch"));
        }

        let deserializer = &mut serde_json::Deserializer::from_slice(&body);
        let value = serde_path_to_error::deserialize(deserializer).map_err(err)?;
        Ok(GithubEvent(value))
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::Router;
    use http_body_util::BodyExt;
    use serde::Deserialize;
    use std::sync::Arc;
    use tower::ServiceExt;

    use super::{GithubEvent, GithubToken};

    #[derive(Debug, Deserialize)]
    struct Event {
        action: String,
    }

    async fn echo(GithubEvent(e): GithubEvent<Event>) -> impl IntoResponse {
        e.action
    }

    fn app() -> Router {
        Router::new()
            .route("/", post(echo))
            .with_state(GithubToken(Arc::new(String::from("42"))))
    }

    async fn body_string(body: Body) -> String {
        String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into()
    }

    fn with_header(v: &'static str) -> Request {
        Request::builder()
            .method("POST")
            .header("X-Hub-Signature-256", v)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn signature_missing() {
        let req = Request::builder()
            .method("POST")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_string(res.into_body()).await, "signature missing");
    }

    #[tokio::test]
    async fn signature_prefix_missing() {
        let res = app().oneshot(with_header("x")).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_string(res.into_body()).await,
            "signature prefix missing"
        );
    }

    #[tokio::test]
    async fn signature_malformed() {
        let res = app().oneshot(with_header("sha256=x")).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_string(res.into_body()).await, "signature malformed");
    }

    #[tokio::test]
    async fn signature_mismatch() {
        let res = app().oneshot(with_header("sha256=01")).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_string(res.into_body()).await, "signature mismatch");
    }

    #[tokio::test]
    async fn signature_valid() {
        let req: Request = Request::builder()
            .method("POST")
            .header(
                "X-Hub-Signature-256",
                "sha256=8b99afd7996c3e3c291a0b54399bacb72016bdb088071de42d1d7156a6a4273d",
            )
            .body(r#"{"action":"hello world"}"#.into())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_string(res.into_body()).await, "hello world");
    }
}
