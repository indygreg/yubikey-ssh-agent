// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! UI elements.

use {
    crate::{agent::SshAgent, Error},
    eframe::epi::{App, Frame},
    egui::{Context, Label, TextEdit},
    log::info,
    once_cell::sync::Lazy,
    ssh_agent::Agent,
    std::{
        fmt::{Display, Formatter},
        ops::Deref,
        path::PathBuf,
        sync::{Arc, Mutex, MutexGuard},
        time::{Duration, Instant},
    },
    winit::dpi::{LogicalPosition, PhysicalPosition},
    zeroize::Zeroizing,
};

#[cfg(target_os = "macos")]
use {
    crate::app::{install_environment_socket, is_environment_socket},
    cocoa::{
        appkit::{
            NSButton, NSControl, NSImage, NSMenu, NSMenuItem, NSSquareStatusItemLength,
            NSStatusBar, NSStatusItem,
        },
        base::{id, nil, NO, YES},
    },
    cocoa_foundation::foundation::{NSAutoreleasePool, NSData, NSDictionary, NSSize, NSString},
    objc::{
        declare::ClassDecl,
        msg_send,
        rc::autoreleasepool,
        runtime::{Class, Object, Sel},
        sel, sel_impl, Message,
    },
    objc_foundation::{INSObject, NSObject},
    objc_id::Id,
    std::{ffi::c_void, ptr::null},
    winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS},
};

const STATUS_BAR_ICON: &[u8] = include_bytes!("key.png");

const HIDE_WINDOW_AFTER_OPERATION_MILLISECONDS: u64 = 2000;

static STATE: Lazy<Arc<Mutex<State>>> = Lazy::new(|| Arc::new(Mutex::new(State::default())));

/// Obtain a new handle on the global state.
pub fn get_state() -> Arc<Mutex<State>> {
    STATE.clone()
}

/// Obtain a handle on the locked state.
pub fn locked_state() -> MutexGuard<'static, State> {
    STATE.lock().expect("unable to lock global state")
}

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
    agent_socket: Option<PathBuf>,
    tray: Option<SystemTray>,
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
            .expect("UI context should be defined")
            .request_repaint()
    }

    fn schedule_repaint(&self, duration: Duration) {
        let ctx = self
            .ctx
            .as_ref()
            .expect("UI context should be defined")
            .clone();

        std::thread::spawn(move || {
            std::thread::sleep(duration);
            ctx.request_repaint();
        });
    }

    pub fn set_agent_thread(&mut self, handle: std::thread::JoinHandle<()>) {
        self.agent_thread = Some(handle);
    }

    pub fn set_agent_socket(&mut self, path: PathBuf) {
        self.agent_socket = Some(path);
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

    pub fn is_environment_socket(&self) -> Result<bool, Error> {
        if let Some(path) = &self.agent_socket {
            is_environment_socket(path)
        } else {
            Ok(false)
        }
    }

    pub fn replace_environment_socket(&self) -> Result<(), Error> {
        if let Some(path) = &self.agent_socket {
            install_environment_socket(path)?;
            self.request_repaint();
            Ok(())
        } else {
            Ok(())
        }
    }
}

/// Called when the menu item to install the SSH_AUTH_SOCK is selected.
fn on_select_install_ssh_auth_sock() -> () {
    info!("installing as environment SSH socket in response to menu select");
    locked_state()
        .replace_environment_socket()
        .expect("error replacing environment socket");
}

trait Tray {
    fn new() -> Self;

    fn reflect_state(&self, state: &State);

    fn outer_position(&self) -> PhysicalPosition<i32>;
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
    #[cfg(target_os = "macos")]
    replace_ssh_socket_item: id,
    #[cfg(target_os = "macos")]
    signing_operations_item: id,
    #[cfg(target_os = "macos")]
    failed_operations_item: id,
}

unsafe impl Sync for SystemTray {}
unsafe impl Send for SystemTray {}

#[cfg(target_os = "macos")]
impl Tray for SystemTray {
    fn new() -> Self {
        unsafe {
            let status_bar =
                NSStatusBar::systemStatusBar(nil).statusItemWithLength_(NSSquareStatusItemLength);

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

            let menu = NSMenu::new(nil);
            let _: () = msg_send![menu, setAutoenablesItems: 0];

            let device_state_item = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("(Unknown Device State)"),
                Sel::from_ptr(null()),
                NSString::alloc(nil).init_str(""),
            );
            device_state_item.setEnabled_(NO);
            menu.addItem_(device_state_item);

            let auth_state_item = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("(Unknown Authentication State)"),
                Sel::from_ptr(null()),
                NSString::alloc(nil).init_str(""),
            );
            auth_state_item.setEnabled_(NO);
            menu.addItem_(auth_state_item);

            menu.addItem_(NSMenuItem::separatorItem(nil));

            let replace_ssh_socket_item = NSMenuItem::alloc(nil)
                .initWithTitle_action_keyEquivalent_(
                    NSString::alloc(nil).init_str("(Unknown Socket State)"),
                    sel!(call),
                    NSString::alloc(nil).init_str(""),
                );

            replace_ssh_socket_item.setEnabled_(NO);
            menu.addItem_(replace_ssh_socket_item);

            menu.addItem_(NSMenuItem::separatorItem(nil));

            let signing_operations_item = NSMenuItem::alloc(nil)
                .initWithTitle_action_keyEquivalent_(
                    NSString::alloc(nil).init_str("0 signing operations"),
                    Sel::from_ptr(null()),
                    NSString::alloc(nil).init_str(""),
                );
            signing_operations_item.setEnabled_(NO);
            menu.addItem_(signing_operations_item);

            let failed_operations_item = NSMenuItem::alloc(nil)
                .initWithTitle_action_keyEquivalent_(
                    NSString::alloc(nil).init_str("0 failed operations"),
                    Sel::from_ptr(null()),
                    NSString::alloc(nil).init_str(""),
                );
            failed_operations_item.setEnabled_(NO);
            menu.addItem_(failed_operations_item);

            menu.addItem_(NSMenuItem::separatorItem(nil));

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
                replace_ssh_socket_item,
                signing_operations_item,
                failed_operations_item,
            }
        }
    }

    fn reflect_state(&self, state: &State) {
        autoreleasepool(|| {
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
                let title = NSString::alloc(nil).init_str(device_title);
                self.device_state_item.setTitle_(title);
                title.autorelease();
                let title = NSString::alloc(nil).init_str(auth_title);
                self.auth_state_item.setTitle_(title);
                title.autorelease();
            }

            let (title, target) = if let Ok(is_env) = state.is_environment_socket() {
                if is_env {
                    ("(Installed as SSH_AUTH_SOCK)", None)
                } else {
                    (
                        "(Click to install as SSH_AUTH_SOCK)",
                        Some(on_select_install_ssh_auth_sock),
                    )
                }
            } else {
                ("(SSH agent Not Running)", None)
            };

            unsafe {
                let title = NSString::alloc(nil).init_str(title);
                self.replace_ssh_socket_item.setTitle_(title);
                title.autorelease();

                if let Some(cb) = target {
                    let cb = Callback::from(Box::new(cb));
                    let _: () = msg_send!(self.replace_ssh_socket_item, setTarget: cb);
                }

                let enabled = if target.is_some() { YES } else { NO };
                self.replace_ssh_socket_item.setEnabled_(enabled);
            }

            unsafe {
                let title = NSString::alloc(nil).init_str(&format!(
                    "{} signing operations",
                    state.signature_operations
                ));
                self.signing_operations_item.setTitle_(title);
                title.autorelease();
                let title = NSString::alloc(nil)
                    .init_str(&format!("{} failed operations", state.failed_operations));
                self.failed_operations_item.setTitle_(title);
                title.autorelease();
            }
        });
    }

    fn outer_position(&self) -> PhysicalPosition<i32> {
        autoreleasepool(|| {
            let window = unsafe {
                self.status_bar
                    .valueForKey_(NSString::alloc(nil).init_str("window"))
            };
            let frame_rect = unsafe { cocoa::appkit::NSWindow::frame(window) };

            let screen = unsafe { cocoa::appkit::NSWindow::screen(window) };

            let position = LogicalPosition::new(
                frame_rect.origin.x as f64,
                core_graphics::display::CGDisplay::main().pixels_high() as f64
                    - (frame_rect.origin.y + frame_rect.size.height),
            );

            let scale_factor = unsafe { cocoa::appkit::NSScreen::backingScaleFactor(screen) };

            position.to_physical(scale_factor)
        })
    }
}

#[cfg(not(target_os = "macos"))]
impl Tray for SystemTray {
    fn new() -> Self {
        Self {}
    }

    fn reflect_state(&self, state: &State) {}

    fn outer_position(&self) -> PhysicalPosition<i32> {
        unimplemented!()
    }
}

#[derive(Default)]
pub struct Ui {}

impl App for Ui {
    fn update(&mut self, ctx: &Context, frame: &mut Frame) {
        let mut state = locked_state();

        if let Some(tray) = &state.tray {
            tray.reflect_state(&state);

            // Position the window under the tray icon. By using the exact
            // position of the tray, we infringe on the status bar space. But
            // the OS thankfully snaps the window out of where it cannot go.
            let tray_pos = tray.outer_position();
            frame.set_window_pos(egui::Pos2 {
                x: tray_pos.x as _,
                y: tray_pos.y as _,
            })
        }

        let panel = egui::CentralPanel::default();

        panel.show(&ctx, |ui| match &mut state.state {
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
        });
    }
}

impl Ui {
    /// Run the UI.
    pub fn run(agent: SshAgent, socket_path: PathBuf) -> ! {
        let options = eframe::NativeOptions {
            always_on_top: true,
            initial_window_size: Some(egui::Vec2::new(180.0, 32.0)),
            decorated: false,
            resizable: false,
            visible: false,
            ..eframe::NativeOptions::default()
        };

        run_app(
            "YubiKey SSH Agent",
            &options,
            Box::new(|cc| {
                let ui = Self::default();
                ui.setup(cc.egui_ctx.clone(), agent, socket_path);

                Box::new(ui)
            }),
        );
    }

    pub fn setup(&self, ctx: Context, agent: SshAgent, socket_path: PathBuf) {
        let mut state = locked_state();
        state.ctx = Some(ctx);
        state.set_agent_socket(socket_path.clone());

        let agent_thread = std::thread::spawn(move || {
            agent
                .run_unix(&socket_path)
                .expect("error running SSH agent")
        });

        state.set_agent_thread(agent_thread);

        if state.tray.is_none() {
            state.tray.replace(SystemTray::new());
        }
    }
}

// Mostly copied from egui_glow crate.
struct RequestRepaintEvent;

#[allow(unsafe_code)]
fn create_display(
    native_options: &epi::NativeOptions,
    window_builder: winit::window::WindowBuilder,
    event_loop: &winit::event_loop::EventLoop<RequestRepaintEvent>,
) -> (
    glutin::WindowedContext<glutin::PossiblyCurrent>,
    glow::Context,
) {
    let gl_window = unsafe {
        glutin::ContextBuilder::new()
            .with_depth_buffer(native_options.depth_buffer)
            .with_multisampling(native_options.multisampling)
            .with_srgb(true)
            .with_stencil_buffer(native_options.stencil_buffer)
            .with_vsync(native_options.vsync)
            .build_windowed(window_builder, event_loop)
            .unwrap()
            .make_current()
            .unwrap()
    };

    let gl = unsafe { glow::Context::from_loader_function(|s| gl_window.get_proc_address(s)) };

    (gl_window, gl)
}

#[cfg(target_os = "macos")]
fn create_event_loop<T>() -> winit::event_loop::EventLoop<T> {
    let mut builder = winit::event_loop::EventLoopBuilder::<T>::with_user_event();

    // Disables docker and menubar but allows user interaction.
    builder.with_activation_policy(ActivationPolicy::Accessory);

    builder.build()
}

#[cfg(not(target_os = "macos"))]
fn create_event_loop<T>() -> winit::event_loop::EventLoop<T> {
    let mut builder = winit::event_loop::EventLoopBuilder::<T>::with_user_event();

    builder.build()
}

#[allow(unsafe_code)]
pub fn run_app(
    app_name: &str,
    native_options: &epi::NativeOptions,
    app_creator: epi::AppCreator,
) -> ! {
    let storage = egui_winit::epi::create_storage(app_name);
    let window_settings = egui_winit::epi::load_window_settings(storage.as_deref());
    let window_builder =
        egui_winit::epi::window_builder(native_options, &window_settings).with_title(app_name);
    let event_loop = create_event_loop();
    let (gl_window, gl) = create_display(native_options, window_builder, &event_loop);
    let gl = std::rc::Rc::new(gl);

    let mut painter = egui_glow::Painter::new(gl.clone(), None, "")
        .unwrap_or_else(|error| panic!("some OpenGL error occurred {}\n", error));

    let mut integration = egui_winit::epi::EpiIntegration::new(
        "egui_glow",
        gl.clone(),
        painter.max_texture_side(),
        gl_window.window(),
        storage,
    );

    {
        let event_loop_proxy = egui::mutex::Mutex::new(event_loop.create_proxy());
        integration.egui_ctx.set_request_repaint_callback(move || {
            event_loop_proxy.lock().send_event(RequestRepaintEvent).ok();
        });
    }

    let mut app = app_creator(&epi::CreationContext {
        egui_ctx: integration.egui_ctx.clone(),
        integration_info: integration.frame.info(),
        storage: integration.frame.storage(),
        gl: gl.clone(),
    });

    if app.warm_up_enabled() {
        integration.warm_up(app.as_mut(), gl_window.window());
    }

    let mut is_focused = true;

    event_loop.run(move |event, _, control_flow| {
        let mut redraw = || {
            #[cfg(feature = "puffin")]
            puffin::GlobalProfiler::lock().new_frame();

            if !is_focused {
                // On Mac, a minimized Window uses up all CPU: https://github.com/emilk/egui/issues/325
                // We can't know if we are minimized: https://github.com/rust-windowing/winit/issues/208
                // But we know if we are focused (in foreground). When minimized, we are not focused.
                // However, a user may want an egui with an animation in the background,
                // so we still need to repaint quite fast.
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            let screen_size_in_pixels: [u32; 2] = gl_window.window().inner_size().into();

            egui_glow::painter::clear(&gl, screen_size_in_pixels, app.clear_color());

            let egui::FullOutput {
                platform_output,
                needs_repaint,
                textures_delta,
                shapes,
            } = integration.update(app.as_mut(), gl_window.window());

            integration.handle_platform_output(gl_window.window(), platform_output);

            let clipped_primitives = { integration.egui_ctx.tessellate(shapes) };

            painter.paint_and_update_textures(
                screen_size_in_pixels,
                integration.egui_ctx.pixels_per_point(),
                &clipped_primitives,
                &textures_delta,
            );

            {
                gl_window.swap_buffers().unwrap();
            }

            {
                *control_flow = if integration.should_quit() {
                    winit::event_loop::ControlFlow::Exit
                } else if needs_repaint {
                    gl_window.window().request_redraw();
                    winit::event_loop::ControlFlow::Poll
                } else {
                    winit::event_loop::ControlFlow::Wait
                };
            }

            integration.maybe_autosave(app.as_mut(), gl_window.window());
        };

        match event {
            // Platform-dependent event handlers to workaround a winit bug
            // See: https://github.com/rust-windowing/winit/issues/987
            // See: https://github.com/rust-windowing/winit/issues/1619
            winit::event::Event::RedrawEventsCleared if cfg!(windows) => redraw(),
            winit::event::Event::RedrawRequested(_) if !cfg!(windows) => redraw(),

            winit::event::Event::WindowEvent { event, .. } => {
                if let winit::event::WindowEvent::Focused(new_focused) = event {
                    is_focused = new_focused;
                }

                if let winit::event::WindowEvent::Resized(physical_size) = &event {
                    gl_window.resize(*physical_size);
                } else if let glutin::event::WindowEvent::ScaleFactorChanged {
                    new_inner_size,
                    ..
                } = &event
                {
                    gl_window.resize(**new_inner_size);
                }

                integration.on_event(app.as_mut(), &event);
                if integration.should_quit() {
                    *control_flow = winit::event_loop::ControlFlow::Exit;
                }

                gl_window.window().request_redraw(); // TODO: ask egui if the events warrants a repaint instead
            }
            winit::event::Event::LoopDestroyed => {
                integration.save(&mut *app, gl_window.window());
                app.on_exit(&gl);
                painter.destroy();
            }
            winit::event::Event::UserEvent(RequestRepaintEvent) => {
                gl_window.window().request_redraw();
            }
            _ => (),
        }
    });
}

// Mostly copied from tray-item-rs.

pub(crate) enum Callback {}
unsafe impl Message for Callback {}

pub(crate) struct CallbackState {
    cb: Box<dyn Fn() -> ()>,
}

impl Callback {
    pub(crate) fn from(cb: Box<dyn Fn() -> ()>) -> Id<Self> {
        let cbs = CallbackState { cb };
        let bcbs = Box::new(cbs);

        let ptr = Box::into_raw(bcbs);
        let ptr = ptr as *mut c_void as usize;
        let mut oid = <Callback as INSObject>::new();
        (*oid).setptr(ptr);
        oid
    }

    pub(crate) fn setptr(&mut self, uptr: usize) {
        unsafe {
            let obj = &mut *(self as *mut _ as *mut ::objc::runtime::Object);
            obj.set_ivar("_cbptr", uptr);
        }
    }
}

// TODO: Drop for $name doesn't get called, probably because objc manages the memory and
// releases it for us.  so we leak the boxed callback right now.

impl INSObject for Callback {
    fn class() -> &'static Class {
        let cname = "Callback";

        let mut klass = Class::get(cname);
        if klass.is_none() {
            let superclass = NSObject::class();
            let mut decl = ClassDecl::new(&cname, superclass).unwrap();
            decl.add_ivar::<usize>("_cbptr");

            extern "C" fn sysbar_callback_call(this: &Object, _cmd: Sel) {
                unsafe {
                    let pval: usize = *this.get_ivar("_cbptr");
                    let ptr = pval as *mut c_void;
                    let ptr = ptr as *mut CallbackState;
                    let bcbs: Box<CallbackState> = Box::from_raw(ptr);
                    {
                        (*bcbs.cb)();
                    }
                    std::mem::forget(bcbs);
                }
            }

            unsafe {
                decl.add_method(
                    sel!(call),
                    sysbar_callback_call as extern "C" fn(&Object, Sel),
                );
            }

            decl.register();
            klass = Class::get(cname);
        }
        klass.unwrap()
    }
}
