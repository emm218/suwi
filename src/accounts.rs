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
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: SecretString,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("username already taken")]
    UsernameTaken,
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
) -> Result<(), CreateError> {
    let hash = hash_password(password)?;

    sqlx::query!(
        "INSERT INTO accounts (id, username, password_hash, registered_at) 
        VALUES (gen_random_uuid(), $1, $2, $3);",
        username,
        hash,
        chrono::Local::now()
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    #[error("invalid credentials")]
    InvalidCredentials,
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
) -> Result<Option<(Uuid, SecretString)>, sqlx::Error> {
    let row: Option<_> = sqlx::query!(
        r#"SELECT id, password_hash FROM accounts WHERE username = $1"#,
        username
    )
    .fetch_optional(pool)
    .await?
    .map(|row| (row.id, row.password_hash.into()));
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
    let (user_id, correct_hash) = get_stored_credentials(username, pool)
        .await?
        .map(|(id, hash)| (Some(id), hash))
        .unwrap_or((
            None,
            "$argon2id$v=19$m=15000,t=2,p=1$\
            gZiV/M1gPc22ElAH/Jh1Hw$\
            CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno"
                .to_string()
                .into(),
        ));

    crate::spawn_blocking_with_tracing(move || verify_password_hash(&correct_hash, &password))
        .await??;

    user_id.ok_or(SignInError::InvalidCredentials)
}
