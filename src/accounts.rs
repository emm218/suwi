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
use argon2::{
    password_hash::{self, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use rand::thread_rng;
use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{spawn_blocking_with_tracing, Settings};

pub mod mfa;
pub use mfa::verify_mfa_challenge;

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("username already taken")]
    UsernameTaken,
    #[error("{0}")]
    InvalidUsername(String),
    #[error(transparent)]
    PasswordHash(#[from] password_hash::Error),
    #[error(transparent)]
    Database(sqlx::Error),
}

impl From<sqlx::Error> for CreateError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(e) = &e
            && e.is_unique_violation()
        {
            Self::UsernameTaken
        } else {
            Self::Database(e)
        }
    }
}

fn hash_password(password: &SecretString) -> password_hash::Result<String> {
    let salt = SaltString::generate(&mut thread_rng());
    Argon2::default()
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map(|p| p.to_string())
}

pub async fn create_account(
    username: &str,
    password: &SecretString,
    pool: &PgPool,
    settings: &Settings,
) -> Result<(), CreateError> {
    if username.is_empty() {
        return Err(CreateError::InvalidUsername(
            "username cannot be empty".to_string(),
        ));
    }

    if username.len() > settings.username_limit {
        return Err(CreateError::InvalidUsername(format!(
            "username cannot be over {} characters",
            settings.username_limit
        )));
    }

    let hash = hash_password(password)?;

    sqlx::query!(
        "INSERT INTO accounts (username, password_hash, registered_at)
        VALUES ($1, $2, now());",
        username,
        hash,
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("need otp")]
    MfaNeeded(Uuid),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    PasswordHash(password_hash::Error),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
}

impl From<password_hash::Error> for SignInError {
    fn from(e: password_hash::Error) -> Self {
        match e {
            password_hash::Error::Password => Self::InvalidCredentials,
            _ => Self::PasswordHash(e),
        }
    }
}

async fn get_stored_credentials(
    username: &str,
    pool: &PgPool,
) -> Result<Option<(Uuid, SecretString, bool)>, sqlx::Error> {
    let row: Option<_> = sqlx::query!(
        r#"SELECT id, password_hash, mfa_enabled
        FROM accounts WHERE username = $1"#,
        username
    )
    .fetch_optional(pool)
    .await?
    .map(|row| (row.id, row.password_hash.into(), row.mfa_enabled));
    Ok(row)
}

fn verify_password_hash(
    correct_hash: &SecretString,
    candidate: &SecretString,
) -> Result<(), SignInError> {
    let correct_hash = PasswordHash::new(correct_hash.expose_secret())?;

    Argon2::default().verify_password(candidate.expose_secret().as_bytes(), &correct_hash)?;

    Ok(())
}

pub async fn verify_credentials(
    username: &str,
    password: SecretString,
    pool: &PgPool,
) -> Result<Uuid, SignInError> {
    let (user_id, correct_hash, mfa_enabled) =
        get_stored_credentials(username, pool).await?.map_or(
            (
                None,
                "$argon2id$v=19$m=15000,t=2,p=1$\
                gZiV/M1gPc22ElAH/Jh1Hw$\
                CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno"
                    .to_string()
                    .into(),
                false,
            ),
            |(id, hash, mfa)| (Some(id), hash, mfa),
        );

    spawn_blocking_with_tracing(move || verify_password_hash(&correct_hash, &password)).await??;

    let user_id = user_id.ok_or(SignInError::InvalidCredentials)?;

    if mfa_enabled {
        Err(SignInError::MfaNeeded(
            mfa::mfa_challenge(user_id, pool).await?,
        ))
    } else {
        Ok(user_id)
    }
}
