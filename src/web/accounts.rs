use std::fmt::Display;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64_STD_NO_PAD, Engine};
use maud::{html, Markup};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, Standard},
    formats::Unpadded,
    serde_as,
};
use tracing::instrument;

use crate::accounts::{
    create_account, mfa::Token as MfaToken, verify_credentials, CreateError as AccountCreateError,
    SignInError,
};

use super::{mfa::mfa_page, JsonOrForm, SuwiState};

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
pub async fn sign_up_handler(
    State((pool, settings)): SuwiState,
    JsonOrForm(Credentials { username, password }): JsonOrForm<Credentials>,
) -> Result<Redirect, AccountCreateError> {
    create_account(&username, &password, &pool, settings.as_ref()).await?;

    Ok(Redirect::to("/sign_in"))
}

pub async fn sign_up_page() -> Markup {
    html! {
        form action="/sign_up" method="post" {
            label for="username" { "username" }
            br;
            input type="text" name="username";
            br;
            label for="password" { "password" }
            br;
            input type="password" name="password";
            br;
            input type="submit" value="submit";
        }
    }
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
            Self::InvalidCredentials => sign_in_page(Some(self)).into_response(),
            Self::MfaNeeded(token) => mfa_page(&token, None).into_response(),
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[instrument(err, skip(pool))]
pub async fn sign_in_handler(
    State((pool, _)): SuwiState,
    JsonOrForm(Credentials { username, password }): JsonOrForm<Credentials>,
) -> Result<String, SignInError> {
    let id = verify_credentials(&username, password, &pool).await?;

    Ok(BASE64_STD_NO_PAD.encode(id.as_bytes()))
}

pub fn sign_in_page<E: Display>(flash: Option<E>) -> Markup {
    html! {
        @if let Some(msg) = flash {
            p class="flash" {(msg)}
        }
        form action="/sign_in" method="post" {
            label for="username" { "username" }
            br;
            input type="text" name="username";
            br;
            label for="password" { "password" }
            br;
            input type="password" name="password";
            br;
            input type="submit" value="submit";
        }
    }
}