/* suwi - a rust activitypub server
 * Copyright (C) 2023 Emmy Emmycelium
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#![feature(let_chains)]

use axum::{
    async_trait,
    extract::{FromRequest, Request, State},
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Form, Json, RequestExt,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64_STD_NO_PAD, Engine};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, Standard},
    formats::Unpadded,
    serde_as,
};
use sqlx::PgPool;
use std::{io, sync::Arc};
use tokio::{
    net::TcpListener,
    task::{spawn_blocking, JoinHandle},
};
use tower_http::trace::TraceLayer;
use tracing::{instrument, Span};

mod accounts;

use accounts::{
    create_account,
    mfa::{Error as MfaError, Token as MfaToken},
    CreateError as AccountCreateError, SignInError,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Settings {
    pub username_limit: usize,
}

type SuwiState = axum::extract::State<(PgPool, Arc<Settings>)>;

struct JsonOrForm<T>(T);

#[async_trait]
impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<()>,
    Form<T>: FromRequest<()>,
    T: 'static,
{
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        if let Some(content_type) = content_type {
            if content_type.starts_with("application/json") {
                let Json(payload) = req.extract().await.map_err(IntoResponse::into_response)?;
                return Ok(Self(payload));
            }

            if content_type.starts_with("application/x-www-form-urlencoded") {
                let Form(payload) = req.extract().await.map_err(IntoResponse::into_response)?;
                return Ok(Self(payload));
            }
        }

        Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response())
    }
}

#[derive(Debug, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: SecretString,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    reason: String,
}

impl IntoResponse for AccountCreateError {
    fn into_response(self) -> Response {
        match self {
            Self::UsernameTaken | Self::InvalidUsername(_) => (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    reason: self.to_string(),
                }),
            )
                .into_response(),
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[instrument(err, skip(pool, settings))]
async fn sign_up_handler(
    State((pool, settings)): SuwiState,
    JsonOrForm(Credentials { username, password }): JsonOrForm<Credentials>,
) -> Result<(), AccountCreateError> {
    create_account(&username, &password, &pool, settings.as_ref()).await
}

#[serde_as]
#[derive(Serialize)]
struct MfaResponse {
    reason: &'static str,
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    token: MfaToken,
}

impl IntoResponse for SignInError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidCredentials => (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    reason: self.to_string(),
                }),
            )
                .into_response(),
            Self::MfaNeeded(token) => (
                StatusCode::BAD_REQUEST,
                Json(MfaResponse {
                    reason: "mfa needed",
                    token,
                }),
            )
                .into_response(),
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[instrument(err, skip(pool))]
async fn sign_in_handler(
    State((pool, _)): SuwiState,
    JsonOrForm(Credentials { username, password }): JsonOrForm<Credentials>,
) -> Result<String, SignInError> {
    let id = accounts::verify_credentials(&username, password, &pool).await?;

    Ok(BASE64_STD_NO_PAD.encode(id.as_bytes()))
}

impl IntoResponse for MfaError {
    fn into_response(self) -> Response {
        match self {
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Self::InvalidOtp(token) => (
                StatusCode::BAD_REQUEST,
                Json(MfaResponse {
                    reason: "invalid otp",
                    token,
                }),
            )
                .into_response(),
            _ => (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    reason: self.to_string(),
                }),
            )
                .into_response(),
        }
    }
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct MfaInfo {
    pub otp: SecretString,
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    pub token: MfaToken,
}

#[instrument(err, skip(pool))]
async fn verify_mfa_handler(
    State((pool, _)): SuwiState,
    JsonOrForm(MfaInfo { otp, token }): JsonOrForm<MfaInfo>,
) -> Result<String, MfaError> {
    let id = accounts::verify_mfa_attempt(&otp, &token, &pool).await?;

    Ok(BASE64_STD_NO_PAD.encode(id.as_bytes()))
}

pub async fn run(listener: TcpListener, pool: PgPool, settings: Settings) -> io::Result<()> {
    let app = axum::Router::new()
        .route("/sign_up", post(sign_up_handler))
        .route("/sign_in", post(sign_in_handler))
        .route("/verify_mfa", post(verify_mfa_handler))
        .with_state((pool, Arc::new(settings)))
        .layer(TraceLayer::new_for_http());

    axum::serve(listener, app).await
}

fn spawn_blocking_with_tracing<F, R>(f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let current_span = Span::current();
    spawn_blocking(move || current_span.in_scope(f))
}
