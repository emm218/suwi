use std::fmt::{self, Display};

use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64_STD_NO_PAD, Engine};
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
use secrecy::{Secret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mfa token expired, please try again")]
    ExpiredToken,
    #[error("incorrect otp")]
    InvalidOtp(Token),
    #[error("invalid mfa token")]
    InvalidToken,
    #[error("totp secret is null")]
    InvalidSecret,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token(Uuid);

impl From<Uuid> for Token {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl TryFrom<Vec<u8>> for Token {
    type Error = uuid::Error;

    fn try_from(mut bytes: Vec<u8>) -> Result<Self, Self::Error> {
        bytes.resize(16, 0);
        Uuid::from_slice(&bytes[..16]).map(Into::into)
    }
}

impl AsRef<[u8]> for Token {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64_STD_NO_PAD.encode(self))
    }
}

pub async fn mfa_challenge(user: Uuid, pool: &PgPool) -> Result<Token, sqlx::Error> {
    sqlx::query_scalar!(
        "INSERT INTO mfa_tokens (user_id, valid_until)
        VALUES ($1, now() + interval '30 minutes') RETURNING id;",
        user,
    )
    .fetch_one(pool)
    .await
    .map(Into::into)
}

pub async fn verify_mfa_attempt(
    otp: &SecretString,
    Token(token): &Token,
    pool: &PgPool,
) -> Result<Uuid, Error> {
    let (secret, valid_until, user_id) = sqlx::query!(
        "DELETE FROM mfa_tokens USING accounts
        WHERE user_id=accounts.id AND mfa_tokens.id=$1
        RETURNING user_id, mfa_secret, valid_until;",
        token
    )
    .fetch_optional(pool)
    .await?
    .ok_or(Error::InvalidToken)
    .map(|row| (row.mfa_secret.map(Into::into), row.valid_until, row.user_id))?;

    let secret = secret.ok_or(Error::InvalidSecret)?;

    if chrono::Local::now() > valid_until {
        Err(Error::ExpiredToken)
    } else if verify_totp(otp, &secret) {
        Ok(user_id)
    } else {
        Err(Error::InvalidOtp(mfa_challenge(user_id, pool).await?))
    }
}

fn verify_totp(candidate: &SecretString, secret: &Secret<Vec<u8>>) -> bool {
    true
}
