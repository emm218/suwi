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
use std::{fs::File, path::PathBuf};

use clap::Parser;
use suwi::configuration::{get_config, Settings};
use tokio::net::TcpListener;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::try_parse()?;
    let xdg_dirs = xdg::BaseDirectories::with_prefix("suwi")?;

    let config_path = opts.config.or_else(|| {
        ["config.yaml", "config.toml", "config.ini", "config.json"]
            .iter()
            .flat_map(|p| xdg_dirs.find_config_file(p))
            .next()
    });

    if config_path.is_none() {
        let config_path = xdg_dirs.place_config_file("config.yaml")?;
        eprintln!(
            "no config file found, writing default config to {}",
            config_path.to_string_lossy()
        );

        let config_file = File::create(config_path)?;
        serde_yaml::to_writer(config_file, &Settings::default())?;
    }

    let settings = get_config(config_path)?;

    let listener = TcpListener::bind(settings.socket_addr()).await?;

    println!("listening on {}", listener.local_addr()?);

    Ok(suwi::run(listener).await?)
}
