// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Main application runtime logic.

use {
    crate::{
        agent::SshAgent,
        ui::{get_state, Ui},
        Config, Error,
    },
    log::warn,
    std::{
        fs::read_link,
        os::unix::fs::symlink,
        path::{Path, PathBuf},
    },
    yubikey::piv::SlotId,
};

const SSH_SOCKET_ENV: &str = "SSH_AUTH_SOCK";

/// Whether the given socket path is installed as `SSH_AUTH_SOCKET`.
pub fn is_environment_socket(path: &Path) -> Result<bool, Error> {
    if let Some(env) = std::env::var_os(SSH_SOCKET_ENV) {
        let env_path = PathBuf::from(env);

        if env_path == path {
            Ok(true)
        } else if let Ok(target) = read_link(&env_path) {
            Ok(target == path)
        } else {
            Ok(false)
        }
    } else {
        Ok(false)
    }
}

/// Install a symlink to `path` in `SSH_AUTH_SOCKET`.
pub fn install_environment_socket(socket_path: &Path) -> Result<(), Error> {
    let env_path = if let Some(v) = std::env::var_os(SSH_SOCKET_ENV) {
        v
    } else {
        return Ok(());
    };

    let env_path = PathBuf::from(env_path);

    if env_path.exists() {
        std::fs::remove_file(&env_path)?;
    }

    warn!(
        "installing symlink {} -> {}",
        env_path.display(),
        socket_path.display()
    );
    symlink(&socket_path, &env_path)?;

    Ok(())
}

pub struct App {}

impl App {
    pub fn new() -> Self {
        Self {}
    }

    pub fn run(self, config: Config, slot_id: SlotId, socket_path: PathBuf) -> Result<(), Error> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if socket_path.exists() {
            std::fs::remove_file(&socket_path)?;
        }

        if config.overwrite_ssh_auth_sock {
            install_environment_socket(&socket_path)?;
        }

        let agent = SshAgent::new(slot_id, get_state());

        Ui::run(agent, socket_path)
    }
}
