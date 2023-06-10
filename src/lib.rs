use axum::body::{Bytes, HttpBody};
use axum::extract::{FromRef, FromRequest};
use axum::http::{Request, StatusCode};
use axum::{async_trait, BoxError};
use hmac_sha256::HMAC;
use serde::de::DeserializeOwned;
use std::fmt::Display;
use std::sync::Arc;
use subtle::ConstantTimeEq;

// State to provide the Github Token to verify Event signature.
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
impl<T, S, B> FromRequest<S, B> for GithubEvent<T>
where
    GithubToken: FromRef<S>,
    T: DeserializeOwned,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
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
    use axum::body::{Body, BoxBody};
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use serde::Deserialize;
    use std::sync::Arc;
    use tower::ServiceExt;

    use super::{GithubEvent, GithubToken};

    #[derive(Debug, Deserialize)]
    struct Event {
        full_name: String,
    }

    async fn echo(GithubEvent(e): GithubEvent<Event>) -> impl IntoResponse {
        e.full_name
    }

    fn app() -> Router {
        Router::new()
            .route("/", get(echo))
            .with_state(GithubToken(Arc::new(String::from("42"))))
    }

    async fn body_string(body: BoxBody) -> String {
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        String::from_utf8_lossy(&bytes).into()
    }

    fn with_header(v: &'static str) -> Request<Body> {
        Request::builder()
            .header("X-Hub-Signature-256", v)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn signature_missing() {
        let req = Request::builder().body(Body::empty()).unwrap();
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
        let req = Request::builder()
            .header(
                "X-Hub-Signature-256",
                "sha256=144b2d11fb144d895276a685a92523c4542265676fdccc17ac7649695da2e7f2",
            )
            .body(r#"{"full_name":"hello world"}"#.into())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_string(res.into_body()).await, "hello world");
    }
}
