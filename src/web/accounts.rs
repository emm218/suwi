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
use serde::{Deserialize, Serialize};
use tracing::instrument;

use super::{JsonOrForm, SuwiState};
use crate::accounts::{
    create_account, mfa::Token as MfaToken, verify_credentials, CreateError as AccountCreateError,
    SignInError,
};

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
            Self::UsernameTaken | Self::InvalidCredentials(_) => {
                sign_up_page(Some(self.to_string().as_str())).into_response()
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[instrument(err, skip(pool, settings))]
pub async fn sign_up(
    State((pool, settings)): SuwiState,
    JsonOrForm(Credentials { username, password }): JsonOrForm<Credentials>,
) -> Result<Redirect, AccountCreateError> {
    create_account(&username, &password, &pool, settings.as_ref()).await?;

    Ok(Redirect::to("/sign_in"))
}

fn sign_up_page(error_msg: Option<&str>) -> Markup {
    html! {
        (super::header())
        h1 { "Sign up" }
        @if let Some(msg) = error_msg {
            p class="flash" {(msg)}
        }
        form action="/sign_up" method="post" {
            label for="username" { "Username" }
            br;
            input type="text" name="username";
            br;
            label for="password" { "Password" }
            br;
            input type="password" name="password";
            br;
            input type="submit" value="Submit";
        }
    }
}

pub async fn get_sign_up(jar: CookieJar) -> (CookieJar, Markup) {
    let error = jar.get("error").map(Cookie::value);

    let page = sign_up_page(error);

    (jar.remove("error"), page)
}

#[derive(Serialize)]
struct MfaResponse {
    reason: &'static str,
    token: MfaToken,
}

impl IntoResponse for SignInError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidCredentials => {
                sign_in_page(Some(self.to_string().as_str())).into_response()
            }
            Self::MfaNeeded(token) => (
                AppendHeaders([(SET_COOKIE, format!("token={token}"))]),
                Redirect::to("/verify_mfa"),
            )
                .into_response(),
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[instrument(err, skip(pool))]
pub async fn sign_in(
    State((pool, _)): SuwiState,
    JsonOrForm(Credentials { username, password }): JsonOrForm<Credentials>,
) -> Result<String, SignInError> {
    verify_credentials(&username, password, &pool)
        .await
        .map(|id| id.to_string())
}

fn sign_in_page(error_msg: Option<&str>) -> Markup {
    html! {
        (super::header())
        h1 { "Sign in" }
        @if let Some(msg) = error_msg {
            p class="flash" {(msg)}
        }
        form action="/sign_in" method="post" {
            label for="username" { "Username" }
            br;
            input type="text" name="username";
            br;
            label for="password" { "Password" }
            br;
            input type="password" name="password";
            br;
            input type="submit" value="Submit";
        }
    }
}

pub async fn get_sign_in(jar: CookieJar) -> (CookieJar, Markup) {
    let error = jar.get("error").map(Cookie::value);

    let page = sign_in_page(error);

    (jar.remove("error"), page)
}
