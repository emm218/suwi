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
use axum::{
    extract::State,
    http::{header::SET_COOKIE, StatusCode},
    response::{AppendHeaders, IntoResponse, Redirect, Response},
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use maud::{html, Markup};
use secrecy::SecretString;
use serde::Deserialize;
use tracing::instrument;

use super::{JsonOrForm, SuwiState};
use crate::accounts::{
    mfa::{Error as MfaError, Token},
    verify_mfa_attempt,
};

impl IntoResponse for MfaError {
    fn into_response(self) -> Response {
        match &self {
            Self::InvalidOtp(token) => {
                page(token.to_string().as_str(), Some(self.to_string().as_str())).into_response()
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

#[derive(Debug, Deserialize)]
pub struct Attempt {
    pub otp: SecretString,
    pub token: Token,
}

#[instrument(err, skip(pool))]
pub async fn verify(
    State((pool, _)): SuwiState,
    JsonOrForm(Attempt { otp, token }): JsonOrForm<Attempt>,
) -> Result<String, MfaError> {
    verify_mfa_attempt(&otp, &token, &pool)
        .await
        .map(|id| id.to_string())
}

fn page(token: &str, error_msg: Option<&str>) -> Markup {
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

pub async fn get(jar: CookieJar) -> Result<(CookieJar, Markup), Response> {
    let token = jar
        .get("token")
        .ok_or(StatusCode::BAD_REQUEST.into_response())?
        .value();

    let page = page(token, None);

    Ok((jar.remove(Cookie::from("token")), page))
}
