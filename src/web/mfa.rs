use axum::{
    extract::State,
    http::{header::SET_COOKIE, StatusCode},
    response::{AppendHeaders, IntoResponse, Redirect, Response},
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
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
        match &self {
            Self::InvalidOtp(token) => {
                mfa_page(token.to_string().as_str(), Some(self.to_string().as_str()))
                    .into_response()
            }
            Self::ExpiredToken | Self::InvalidToken | Self::InvalidSecret => (
                AppendHeaders([(SET_COOKIE, format!("error={self}"))]),
                Redirect::to("/sign_in"),
            )
                .into_response(),
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

pub fn mfa_page(token: &str, error_msg: Option<&str>) -> Markup {
    html! {
        (super::header())
        h1 { "Sign in" }
        @if let Some(msg) = error_msg {
            p class="flash" {(msg)}
        }
        form action="/verify_mfa" method="post" {
            input type="hidden" name="token" value=(token);
            label for="otp" { "Authenticator code" }
            br;
            input type="text" name="otp";
            br;
            input type="submit" value="Submit";
        }
    }
}

pub async fn mfa_get_handler(jar: CookieJar) -> Result<(CookieJar, Markup), Response> {
    let token = jar
        .get("token")
        .ok_or(StatusCode::BAD_REQUEST.into_response())?
        .value();

    let page = mfa_page(token, None);

    Ok((jar.remove(Cookie::from("token")), page))
}
