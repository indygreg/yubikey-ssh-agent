// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Main application runtime logic.

use {
    crate::{
        agent::SshAgent,
        ui::{State, Ui},
        Config, Error,
    },
    ssh_agent::Agent,
    std::{
        fs::read_link,
        os::unix::fs::symlink,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
        thread,
    },
    yubikey::piv::SlotId,
};

/// Whether the given socket path is installed as `SSH_AUTH_SOCKET`.
pub fn is_environment_socket(path: &Path) -> Result<bool, Error> {
    if let Some(env) = std::env::var_os("SSH_AUTH_SOCKET") {
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
    let env_path = if let Some(v) = std::env::var_os("SSH_AUTH_SOCK") {
        v
    } else {
        return Ok(());
    };

    let env_path = PathBuf::from(env_path);

    if env_path.exists() {
        std::fs::remove_file(&env_path)?;
    }

    symlink(&socket_path, &env_path)?;

    Ok(())
}

pub struct App {
    ui: Ui,
}

impl App {
    pub fn new() -> Self {
        Self { ui: Ui::new() }
    }

    pub fn state(&self) -> Arc<Mutex<State>> {
        self.ui.get_state()
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

        self.ui
            .get_state()
            .lock()
            .expect("should be able to lock state")
            .set_agent_socket(socket_path.clone());

        let agent = SshAgent::new(slot_id, self.state());

        let agent_thread = thread::spawn(move || {
            agent
                .run_unix(&socket_path)
                .expect("error running SSH agent")
        });

        self.ui
            .get_state()
            .lock()
            .expect("should be able to lock state")
            .set_agent_thread(agent_thread);

        let options = eframe::NativeOptions {
            always_on_top: true,
            initial_window_size: Some(egui::Vec2::new(180.0, 128.0)),
            resizable: false,
            visible: false,
            ..eframe::NativeOptions::default()
        };

        crate::ui::run_app(
            "YubiKey SSH Agent",
            &options,
            Box::new(|cc| {
                let ui = self.ui;
                ui.setup(cc.egui_ctx.clone());

                Box::new(ui)
            }),
        );
    }
}
