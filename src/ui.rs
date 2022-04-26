// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! UI elements.

use {
    crate::Error,
    eframe::epi::{App, Frame},
    egui::{Color32, Context, Label, TextEdit},
    std::{
        fmt::{Display, Formatter},
        ops::Deref,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    },
    zeroize::Zeroizing,
};

#[cfg(target_os = "macos")]
use {
    cocoa::{
        appkit::{
            NSApp, NSApplication, NSButton, NSImage, NSMenu, NSMenuItem, NSSquareStatusItemLength,
            NSStatusBar, NSStatusItem,
        },
        base::{id, nil, NO, YES},
    },
    cocoa_foundation::foundation::{NSAutoreleasePool, NSData, NSSize, NSString},
    objc::{msg_send, runtime::Sel, sel, sel_impl},
    std::{ffi::c_void, ptr::null},
};

const STATUS_BAR_ICON: &[u8] = include_bytes!("key.png");

const HIDE_WINDOW_AFTER_OPERATION_MILLISECONDS: u64 = 3000;

pub enum AppState {
    /// Waiting for something to happen.
    Waiting,
    /// PIN is needed.
    ///
    /// State when the agent requests a PIN but the UI hasn't responded yet.
    PinRequested,

    /// UI received the request for PIN and is collecting input from user.
    ///
    /// First element is whether we stole focus.
    PinWaiting(bool, String),

    /// User submitted a PIN.
    ///
    /// Waiting for agent to pick it up.
    PinEntered(Zeroizing<String>),

    /// User denied request to enter PIN.
    PinEntryDenied,

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

pub enum PinEntry {
    Pin(Zeroizing<String>),
    Denied,
}

#[derive(Default)]
pub struct State {
    session_opened: bool,
    auth_state: AuthenticationState,
    state: AppState,
    failed_operations: u64,
    signature_operations: u64,
    agent_thread: Option<std::thread::JoinHandle<()>>,
    ctx: Option<Context>,
}

impl Deref for State {
    type Target = AppState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl State {
    fn request_repaint(&self) {
        self.ctx
            .as_ref()
            .expect("UI frame should be defined")
            .request_repaint()
    }

    fn schedule_repaint(&self, duration: Duration) {
        let ctx = self
            .ctx
            .as_ref()
            .expect("UI frame should be defined")
            .clone();

        std::thread::spawn(move || {
            std::thread::sleep(duration);
            ctx.request_repaint();
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

        Ok(())
    }

    /// Retrieve the collected pin.
    pub fn retrieve_pin(&mut self) -> Option<PinEntry> {
        match &self.state {
            AppState::PinEntered(pin) => {
                let pin = pin.clone();
                self.state = AppState::PinResultPending;
                self.request_repaint();

                Some(PinEntry::Pin(pin))
            }
            AppState::PinEntryDenied => {
                self.state = AppState::PinResultPending;
                self.request_repaint();

                Some(PinEntry::Denied)
            }
            _ => None,
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

trait Tray {
    fn new() -> Self;

    fn reflect_state(&self, state: &State);
}

pub struct SystemTray {
    #[cfg(target_os = "macos")]
    status_bar: id,
    #[cfg(target_os = "macos")]
    menu: id,
    #[cfg(target_os = "macos")]
    device_state_item: id,
    #[cfg(target_os = "macos")]
    auth_state_item: id,
}

#[cfg(target_os = "macos")]
impl Tray for SystemTray {
    fn new() -> Self {
        unsafe {
            let app = NSApp();
            app.activateIgnoringOtherApps_(YES);

            let status_bar = NSStatusBar::systemStatusBar(nil)
                .autorelease()
                .statusItemWithLength_(NSSquareStatusItemLength);

            let title = NSString::alloc(nil).init_str("YubiKey SSH Agent");
            status_bar.setTitle_(title);

            let icon = status_bar.button();
            let icon_data = NSData::dataWithBytes_length_(
                nil,
                STATUS_BAR_ICON.as_ptr() as *const c_void,
                STATUS_BAR_ICON.len() as u64,
            );
            let icon_image = NSImage::initWithData_(NSImage::alloc(nil), icon_data);
            let icon_size = NSSize::new(18.0, 18.0);
            icon.setImage_(icon_image);
            let _: () = msg_send![icon_image, setSize: icon_size];
            let _: () = msg_send![icon_image, setTemplate: NO];

            let menu = NSMenu::new(nil).autorelease();

            let device_state_item = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("(Unknown Device State)"),
                Sel::from_ptr(null()),
                NSString::alloc(nil).init_str(""),
            );
            menu.addItem_(device_state_item);

            let auth_state_item = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("(Unknown Authentication State)"),
                Sel::from_ptr(null()),
                NSString::alloc(nil).init_str(""),
            );
            menu.addItem_(auth_state_item);

            menu.addItem_(NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("Quit"),
                sel!(terminate:),
                NSString::alloc(nil).init_str(""),
            ));

            status_bar.setMenu_(menu);

            Self {
                status_bar,
                menu,
                device_state_item,
                auth_state_item,
            }
        }
    }

    fn reflect_state(&self, state: &State) {
        let (device_title, auth_title) = if state.session_opened {
            let device = "YubiKey Active";

            let auth = match state.auth_state {
                AuthenticationState::Unknown => "Unknown Key Lock State",
                AuthenticationState::Authenticated => "Key Unlocked",
                AuthenticationState::Unauthenticated => "Key Locked",
            };

            (device, auth)
        } else {
            ("YubiKey Inactive", "Key Not Available")
        };

        unsafe {
            self.device_state_item
                .setTitle_(NSString::alloc(nil).init_str(device_title));
            self.auth_state_item
                .setTitle_(NSString::alloc(nil).init_str(auth_title))
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl Tray for SystemTray {
    fn new() -> Self {
        Self {}
    }

    fn reflect_state(&self, state: &State) {}
}

pub struct Ui {
    state: Arc<Mutex<State>>,
    tray: SystemTray,
}

impl App for Ui {
    fn update(&mut self, ctx: &Context, frame: &mut Frame) {
        let mut state = self.state.lock().expect("unable to acquire state lock");

        self.tray.reflect_state(&state);

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
                    state.state = AppState::PinWaiting(false, "".into());
                    frame.set_window_visibility(Some(true));
                    ctx.request_repaint();
                }
                AppState::PinWaiting(focused, pin) => {
                    frame.set_window_visibility(Some(true));

                    if !*focused {
                        frame.set_window_focus(true);
                        *focused = true;
                    }

                    let (text_response, unlock_response, deny_response) = ui
                        .horizontal(|ui| {
                            let text_edit = TextEdit::singleline(pin)
                                .password(true)
                                .hint_text("PIN")
                                .desired_width(40.0);

                            let text = ui.add(text_edit);
                            let unlock = ui.button("Unlock");
                            let deny = ui.button("Deny");

                            (text, unlock, deny)
                        })
                        .inner;

                    let pin_entered = (text_response.lost_focus()
                        && ui.input().key_pressed(egui::Key::Enter))
                        || unlock_response.clicked();

                    if deny_response.clicked() {
                        state.state = AppState::PinEntryDenied;
                        ctx.request_repaint();
                    } else if pin_entered {
                        state.state = AppState::PinEntered(Zeroizing::new(pin.clone()));
                        ctx.request_repaint();
                    } else {
                        text_response.request_focus();
                    }
                }
                AppState::PinEntered(_) => {
                    ui.add(Label::new("(waiting on agent to use PIN)"));
                }
                AppState::PinEntryDenied => {
                    ui.add(Label::new("(waiting on agent to see PIN refusal)"));
                }
                AppState::PinResultPending => {
                    ui.add(Label::new("(waiting on PIN attempt result)"));
                }
                AppState::PinAccepted(hide_time) => {
                    ui.add(Label::new("The PIN is valid!"));

                    if Instant::now() >= *hide_time {
                        state.state = AppState::Waiting;
                        frame.set_window_visibility(Some(false));
                        ctx.request_repaint();
                    }
                }
                AppState::PinRejected(hide_time) => {
                    ui.add(Label::new("The PIN was rejected"));

                    if Instant::now() >= *hide_time {
                        state.state = AppState::Waiting;
                        frame.set_window_visibility(Some(false));
                        ctx.request_repaint();
                    }
                }
            }
        });
    }
}

impl Ui {
    pub fn new() -> Self {
        let tray = SystemTray::new();

        Self {
            state: Arc::new(Mutex::new(State::default())),
            tray,
        }
    }

    pub fn get_state(&self) -> Arc<Mutex<State>> {
        self.state.clone()
    }

    pub fn setup(&self, ctx: Context) {
        let mut state = self.state.lock().expect("unable to lock state");
        state.ctx = Some(ctx);
    }
}
