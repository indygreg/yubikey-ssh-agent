// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! UI elements.

use {
    crate::Error,
    eframe::epi::{Frame, Storage},
    egui::{Color32, Context, Label, TextEdit},
    notify_rust::Notification,
    std::{
        fmt::{Display, Formatter},
        ops::Deref,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    },
    zeroize::Zeroizing,
};

const HIDE_WINDOW_AFTER_OPERATION_MILLISECONDS: u64 = 3000;

pub enum AppState {
    /// Waiting for something to happen.
    Waiting,
    /// PIN is needed.
    ///
    /// State when the agent requests a PIN but the UI hasn't responded yet.
    PinRequested,

    /// UI received the request for PIN and is collecting input from user.
    PinWaiting(String),

    /// User submitted a PIN.
    ///
    /// Waiting for agent to pick it up.
    PinEntered(Zeroizing<String>),

    /// Agent retrieved the PIN.
    ///
    /// Waiting on it to post a status update.
    PinResultPending,

    /// Agent accepted a valid PIN.
    PinAccepted(Instant),

    /// Agent rejected the PIN.
    PinRejected(Instant),
}

impl Default for AppState {
    fn default() -> Self {
        Self::Waiting
    }
}

pub enum AuthenticationState {
    Unknown,
    Authenticated,
    Unauthenticated,
}

impl Display for AuthenticationState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown",
            Self::Authenticated => "authenticated",
            Self::Unauthenticated => "unauthenticated",
        })
    }
}

impl Default for AuthenticationState {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Default)]
pub struct State {
    session_opened: bool,
    auth_state: AuthenticationState,
    state: AppState,
    failed_operations: u64,
    signature_operations: u64,
    agent_thread: Option<std::thread::JoinHandle<()>>,
    frame: Option<Frame>,
}

impl Deref for State {
    type Target = AppState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl State {
    fn request_repaint(&self) {
        self.frame
            .as_ref()
            .expect("UI frame should be defined")
            .request_repaint()
    }

    fn schedule_repaint(&self, duration: Duration) {
        let frame = self
            .frame
            .as_ref()
            .expect("UI frame should be defined")
            .clone();

        std::thread::spawn(move || {
            std::thread::sleep(duration);
            frame.request_repaint();
        });
    }

    pub fn set_agent_thread(&mut self, handle: std::thread::JoinHandle<()>) {
        self.agent_thread = Some(handle);
    }

    /// Define whether a device is actively connected.
    pub fn set_session_opened(&mut self, value: bool) {
        self.session_opened = value;
        self.request_repaint();
    }

    pub fn set_authentication(&mut self, auth: AuthenticationState) {
        self.auth_state = auth;
        self.request_repaint();
    }

    /// Request the retrieval of a PIN to unlock.
    pub fn request_pin(&mut self) -> Result<(), Error> {
        self.state = AppState::PinRequested;
        self.request_repaint();

        Notification::new()
            .summary("YubiKey pin needed")
            .body("SSH is requesting you to unlock your YubiKey")
            .timeout(5000)
            .show()?;

        Ok(())
    }

    /// Retrieve the collected pin.
    pub fn retrieve_pin(&mut self) -> Option<Zeroizing<String>> {
        if let AppState::PinEntered(pin) = &self.state {
            let pin = pin.clone();
            self.state = AppState::PinResultPending;
            self.request_repaint();

            Some(pin)
        } else {
            None
        }
    }

    pub fn pin_accepted(&mut self) {
        let delay = Duration::from_millis(HIDE_WINDOW_AFTER_OPERATION_MILLISECONDS);
        let hide_time = Instant::now() + delay;

        self.state = AppState::PinAccepted(hide_time);
        self.request_repaint();
        self.schedule_repaint(delay);
    }

    pub fn pin_rejected(&mut self) {
        let delay = Duration::from_millis(HIDE_WINDOW_AFTER_OPERATION_MILLISECONDS);
        let hide_time = Instant::now() + delay;

        self.state = AppState::PinRejected(hide_time);
        self.request_repaint();
        self.schedule_repaint(delay);
    }

    pub fn record_failed_operation(&mut self) {
        self.failed_operations += 1;
        self.request_repaint();
    }

    pub fn record_signing_operation(&mut self) {
        self.signature_operations += 1;
        self.request_repaint();
    }
}

pub struct App {
    state: Arc<Mutex<State>>,
}

impl eframe::epi::App for App {
    fn setup(&mut self, _ctx: &egui::Context, frame: &Frame, _storage: Option<&dyn Storage>) {
        let mut state = self.state.lock().expect("unable to lock state");

        state.frame = Some(frame.clone());
    }

    fn update(&mut self, ctx: &Context, frame: &Frame) {
        let mut state = self.state.lock().expect("unable to acquire state lock");

        let panel = egui::CentralPanel::default();

        panel.show(&ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Active Connection?");

                if state.session_opened {
                    ui.colored_label(
                        match state.auth_state {
                            AuthenticationState::Unknown => Color32::BLUE,
                            AuthenticationState::Authenticated => Color32::GREEN,
                            AuthenticationState::Unauthenticated => Color32::RED,
                        },
                        "yes",
                    );
                } else {
                    ui.label("no");
                }
            });

            ui.label(format!(
                "Signing operations: {}",
                state.signature_operations
            ));
            ui.label(format!("Failed operations: {}", state.failed_operations));

            ui.separator();

            match &mut state.state {
                AppState::Waiting => {
                    ui.add(Label::new("(waiting for PIN request)"));
                }
                AppState::PinRequested => {
                    state.state = AppState::PinWaiting("".into());
                    frame.lock().output.window_visibility = Some(true);
                    ctx.request_repaint();
                }
                AppState::PinWaiting(pin) => {
                    frame.lock().output.window_visibility = Some(true);

                    let (text_response, button_response) = ui
                        .horizontal(|ui| {
                            let text_edit = TextEdit::singleline(pin)
                                .password(true)
                                .hint_text("PIN")
                                .desired_width(40.0);

                            let text = ui.add(text_edit);
                            let button = ui.button("Unlock");

                            (text, button)
                        })
                        .inner;

                    let pin_entered = (text_response.lost_focus()
                        && ui.input().key_pressed(egui::Key::Enter))
                        || button_response.clicked();

                    if pin_entered {
                        state.state = AppState::PinEntered(Zeroizing::new(pin.clone()));
                        ctx.request_repaint();
                    } else {
                        text_response.request_focus();
                    }
                }
                AppState::PinEntered(_) => {
                    ui.add(Label::new("(waiting on agent to use PIN)"));
                }
                AppState::PinResultPending => {
                    ui.add(Label::new("(waiting on PIN attempt result)"));
                }
                AppState::PinAccepted(hide_time) => {
                    ui.add(Label::new("The PIN is valid!"));

                    if Instant::now() >= *hide_time {
                        state.state = AppState::Waiting;
                        frame.lock().output.window_visibility = Some(false);
                        ctx.request_repaint();
                    }
                }
                AppState::PinRejected(hide_time) => {
                    ui.add(Label::new("The PIN was rejected"));

                    if Instant::now() >= *hide_time {
                        state.state = AppState::Waiting;
                        frame.lock().output.window_visibility = Some(false);
                        ctx.request_repaint();
                    }
                }
            }
        });
    }

    fn name(&self) -> &str {
        "YubiKey SSH Agent"
    }
}

pub struct Ui {
    app: App,
}

impl Ui {
    pub fn new() -> Self {
        Self {
            app: App {
                state: Arc::new(Mutex::new(State::default())),
            },
        }
    }

    pub fn state(&self) -> Arc<Mutex<State>> {
        self.app.state.clone()
    }

    pub fn run(self) {
        let options = eframe::NativeOptions {
            always_on_top: true,
            decorated: false,
            initial_window_size: Some(egui::Vec2::new(180.0, 128.0)),
            resizable: false,
            visible: false,
            ..eframe::NativeOptions::default()
        };

        eframe::run_native(Box::new(self.app), options);
    }
}
