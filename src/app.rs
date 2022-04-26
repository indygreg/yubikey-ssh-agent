// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Main application runtime logic.

use {
    crate::{
        agent::SshAgent,
        ui::{State, Ui},
    },
    ssh_agent::Agent,
    std::{
        path::PathBuf,
        sync::{Arc, Mutex},
        thread,
    },
    yubikey::piv::SlotId,
};

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

    pub fn run(self, slot_id: SlotId, socket_path: PathBuf) -> ! {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).expect("unable to create directory for socket");
        }

        if socket_path.exists() {
            std::fs::remove_file(&socket_path)
                .expect("should be able to remove existing socket file");
        }

        let agent = SshAgent::new(slot_id, self.state());

        let agent_thread = thread::spawn(move || {
            agent
                .run_unix(&socket_path)
                .expect("agent should exit cleanly");
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

        eframe::run_native(
            "YubiKey SSH Agent",
            options,
            Box::new(|cc| {
                let ui = self.ui;
                ui.setup(cc.egui_ctx.clone());

                Box::new(ui)
            }),
        );
    }
}
