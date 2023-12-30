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
#![feature(async_closure)]

use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{io, sync::Arc};
use tokio::{
    net::TcpListener,
    task::{spawn_blocking, JoinHandle},
};
use tower_http::trace::TraceLayer;
use tracing::Span;
use web::{
    accounts::{sign_in_handler, sign_in_page, sign_up_handler, sign_up_page},
    mfa::verify_mfa_handler,
};

mod accounts;
mod web;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub username_limit: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            username_limit: 100,
        }
    }
}

pub async fn run(listener: TcpListener, pool: PgPool, settings: Settings) -> io::Result<()> {
    let app = axum::Router::new()
        .route("/sign_up", get(sign_up_page).post(sign_up_handler))
        .route(
            "/sign_in",
            get(async || sign_in_page::<&str>(None)).post(sign_in_handler),
        )
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
