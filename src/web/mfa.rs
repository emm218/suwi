use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64_STD_NO_PAD, Engine};
use maud::{html, Markup};
use secrecy::SecretString;
use serde::Deserialize;
use serde_with::{
    base64::{Base64, Standard},
    formats::Unpadded,
    serde_as,
};
use tracing::instrument;

use crate::accounts::{
    mfa::{Error as MfaError, Token as MfaToken},
    verify_mfa_attempt,
};

use super::{JsonOrForm, SuwiState};

impl IntoResponse for MfaError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidOtp(token) => mfa_page(&token, Some(self)).into_response(),
            Self::ExpiredToken | Self::InvalidToken | Self::InvalidSecret => {
                Redirect::to("/sign_in").into_response()
            }
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct MfaAttempt {
    pub otp: SecretString,
    #[serde_as(as = "Base64<Standard, Unpadded>")]
    pub token: MfaToken,
}

#[instrument(err, skip(pool))]
pub async fn verify_mfa_handler(
    State((pool, _)): SuwiState,
    JsonOrForm(MfaAttempt { otp, token }): JsonOrForm<MfaAttempt>,
) -> Result<String, MfaError> {
    let id = verify_mfa_attempt(&otp, &token, &pool).await?;

    Ok(BASE64_STD_NO_PAD.encode(id.as_bytes()))
}

pub fn mfa_page(token: &MfaToken, flash: Option<MfaError>) -> Markup {
    html! {
        @if let Some(msg) = flash {
            p class="flash" {(msg)}
        }
        form action="/verify_mfa" method="post" {
            input type="hidden" name="token" value=(BASE64_STD_NO_PAD.encode(token));
            label for="otp" { "authenticator code" }
            br;
            input type="text" name="otp";
            br;
            input type="submit" value="submit";
        }
    }
}
