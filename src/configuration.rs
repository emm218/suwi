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
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AppSettings {
    pub host: IpAddr,
    pub port: u16,
}

impl AppSettings {
    pub fn socket_addr(&self) -> SocketAddr {
        std::net::SocketAddr::new(self.host, self.port)
    }
}

#[derive(Serialize, Deserialize)]
pub struct DatabaseSettings {
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: Option<SecretString>,
    pub name: String,
}

impl DatabaseSettings {
    pub fn connection_string(&self) -> SecretString {
        match &self.password {
            None => format!(
                "postgres://{}@{}:{}/{}",
                self.username, self.host, self.port, self.name
            ),
            Some(p) => format!(
                "postgres://{}:{}@{}:{}/{}",
                self.username,
                p.expose_secret(),
                self.host,
                self.port,
                self.name
            ),
        }
        .into()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Settings {
    pub application: AppSettings,
    pub database: DatabaseSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            application: AppSettings {
                port: 8000,
                host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            },
            database: DatabaseSettings {
                username: "postgres".to_string(),
                password: None,
                port: 5432,
                host: "127.0.0.1".to_string(),
                name: "suwi".to_string(),
            },
        }
    }
}

pub fn get_config(path: Option<PathBuf>) -> Result<Settings, config::ConfigError> {
    let mut builder = config::Config::builder()
        .set_default("application.port", 8000)?
        .set_default("application.host", "127.0.0.1")?
        .set_default("database.port", 5432)?
        .set_default("database.host", "127.0.0.1")?
        .set_default("database.username", "postgres")?
        .set_default("database.name", "suwi")?;

    builder = if let Some(path) = path {
        builder.add_source(config::File::from(path))
    } else {
        builder
    }
    .add_source(config::Environment::with_prefix("suwi").separator("_"));

    builder.build()?.try_deserialize()
}
