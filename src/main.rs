// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Opinionated SSH agent for YubiKeys.
//!
//! This program acts as an SSH agent for YubiKeys.
//!
//! Usage:
//!
//!   $ yubikey-ssh-agent --socket ~/.yubikey-ssh-agent.sock
//!   $ export SSH_AUTH_SOCK=~/.yubikey-ssh-agent.sock
//!   $ ssh ...
//!
//! The agent automatically exposes keys in PIV slots in YubiKeys.

pub mod agent;
pub mod ui;

use {
    crate::agent::SshAgent,
    clap::{ArgGroup, Parser},
    log::{error, warn},
    ssh_agent::Agent,
    std::{path::PathBuf, str::FromStr, thread},
    thiserror::Error,
    yubikey::{piv::SlotId, Error as YkError},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("notify error: {0}")]
    Notify(#[from] notify_rust::error::Error),

    #[error("SSH protocol error: {0}")]
    Proto(#[from] ssh_agent::proto::ProtoError),

    #[error("SSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),

    #[error("YubiKey error: {0}")]
    YubiKey(#[from] YkError),

    #[error("locking error: {0}")]
    Lock(&'static str),

    #[error("X.509 certificate error: {0}")]
    X509(#[from] x509_certificate::X509CertificateError),

    #[error("SmartCard authentication failed")]
    SmartcardFailedAuthentication,
}

/// An opinionated SSH Agent for YubiKeys.
///
/// This program acts as an SSH agent. An SSH agent is a process that an
/// SSH client consults when performing operations. The typical role of an
/// SSH agent is to collect registered SSH keys so SSH clients can later use
/// them.
///
/// This SSH agent is purpose built to serve as a bridge between an SSH
/// client and an attached YubiKey.
///
/// The agent automatically exposes keys in the requested PIV slots. Slot
/// 9a is most commonly used for holding SSH keys.
///
/// # Usage
///
/// First, start up the agent:
///
/// $ yubikey-ssh-agent --socket /tmp/yubikey-ssh.sock
///
/// Then, tell SSH how to use it:
///
/// $ export SSH_AUTH_SOCK=/tmp/yubikey-ssh.sock
///
/// Then perform an SSH operation needing the private key on your YubiKey:
///
/// $ ssh git@github.com
///
/// # Security Considerations
///
/// This agent does not attempt to export private keys from the hardware device.
/// (If you generate private keys directly on the hardware device it is
/// actually impossible to export the private keys.) So there should be no
/// potential to exfiltrate private keys using this software.
///
/// This agent does not cache your unlock PIN or management key. So if the
/// memory of this agent's process is dumped, you'd only have access to the
/// PIN or management key if an authentication operation were in progress.
///
/// This agent maintains a long-lived connection with the YubiKey. Depending
/// on the settings of the PIV slot, a prior authentication (e.g. PIN unlock)
/// could carry forward to a subsequent operation. To prevent this, change the
/// PIV authentication requirements for the slot to require authentication on
/// every operation. This will likely result in more PIN requests than before
/// and this behavior can be burdensome if establishing many SSH sessions or
/// connections drop frequently and need to be re-keyed.
///
/// This agent also does not allow registering non-YubiKey keys. Therefore it
/// doesn't keep private key data around in memory. Therefore the general
/// threat of anybody being able to dump memory of an SSH agent process to
/// recover private keys does not apply.
///
/// General threat vectors around unwanted parties initiating malicious requests
/// through SSH agents still apply. From an SSH agent's perspective, it is
/// difficult to impossible to authenticate who is making a request for an
/// operation. So the best you can do is limit who can send requests to the SSH
/// agent process. This entails best practices like not listening on external
/// network interfaces, not forwarding your agent to remote machines, and
/// limiting who can write to the UNIX domain socket. (We restrict writing
/// to the current user by default.)
///
#[derive(Parser)]
#[clap(arg_required_else_help(true))]
#[clap(group(
            ArgGroup::new("bind")
                .required(true)
                .args(&["socket", "tcp"]),
        ))]
struct Cli {
    /// Path to UNIX domain socket to bind to.
    #[clap(long)]
    socket: Option<PathBuf>,

    /// TCP address:port to bind to.
    #[clap(long)]
    tcp: Option<String>,

    /// YubiKey key slot to use.
    #[clap(default_value = "9a", long)]
    slot: String,
}

#[cfg(target_os = "macos")]
fn supplement_notifications() -> Result<(), Error> {
    let identifier = notify_rust::get_bundle_identifier_or_default("yubikey-ssh-agent");
    notify_rust::set_application(&identifier).expect("unable to set notifying application");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn supplement_notifications() -> Result<(), Error> {
    Ok(())
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    supplement_notifications().unwrap();

    let cli = Cli::parse();

    let slot = SlotId::from_str(&cli.slot).expect("illegal slot value; try 9a");
    warn!("using slot {:?}", slot);

    let ui = crate::ui::Ui::new();
    let state = ui.state();

    let agent = SshAgent::new(slot, state.clone());

    let agent_thread = thread::spawn(|| {
        if let Some(path) = cli.socket {
            if path.exists() {
                std::fs::remove_file(&path).unwrap();
            }

            warn!("To use this agent process:");
            warn!("export SSH_AUTH_SOCK={}", path.display());

            agent.run_unix(&path).expect("agent should exit cleanly")
        } else if let Some(address) = cli.tcp {
            agent.run_tcp(&address).expect("agent should exit cleanly")
        } else {
            panic!("argument parsing bug");
        }
    });

    state
        .lock()
        .expect("should be able to get state")
        .set_agent_thread(agent_thread);

    // The event loop needs to run on the main thread (at least on macOS).
    // And the agent also runs indefinitely.
    ui.run();
}
