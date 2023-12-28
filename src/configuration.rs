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

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Settings {
    pub port: u16,
    pub host: IpAddr,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 8000,
            host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        }
    }
}

impl Settings {
    pub fn socket_addr(&self) -> SocketAddr {
        std::net::SocketAddr::new(self.host, self.port)
    }
}

pub fn get_config(path: Option<PathBuf>) -> Result<Settings, config::ConfigError> {
    let mut builder = config::Config::builder()
        .set_default("port", 8000)?
        .set_default("host", "127.0.0.1")?;

    builder = if let Some(path) = path {
        builder.add_source(config::File::from(path))
    } else {
        builder
    }
    .add_source(config::Environment::with_prefix("suwi"));

    builder.build()?.try_deserialize()
}
