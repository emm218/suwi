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
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mfa token has expired")]
    ExpiredToken,
    #[error("invalid otp")]
    InvalidOtp,
    #[error("otp secret is null")]
    InvalidSecret,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub async fn mfa_challenge(user: Uuid, pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar!(
        "INSERT INTO mfa_tokens (user_id, valid_until)
        VALUES ($1, now() + interval '30 minutes') RETURNING id;",
        user,
    )
    .fetch_one(pool)
    .await
}

pub async fn verify_mfa_challenge(
    otp: &SecretString,
    token: &Uuid,
    pool: &PgPool,
) -> Result<Uuid, Error> {
    let (secret, valid_until, user_id) = sqlx::query!(
        "SELECT mfa_secret, valid_until, user_id
        FROM mfa_tokens JOIN accounts ON user_id = accounts.id
        WHERE mfa_tokens.id = $1;",
        token
    )
    .fetch_one(pool)
    .await
    .map(|row| (row.mfa_secret.map(Into::into), row.valid_until, row.user_id))?;

    if let Some(secret) = secret {
        if chrono::Local::now() > valid_until {
            Err(Error::ExpiredToken)
        } else if verify_totp(otp, &secret) {
            Ok(user_id)
        } else {
            Err(Error::InvalidOtp)
        }
    } else {
        // something has gone very wrong...
        Err(Error::InvalidSecret)
    }
}

fn verify_totp(candidate: &SecretString, secret: &Secret<Vec<u8>>) -> bool {
    true
}
