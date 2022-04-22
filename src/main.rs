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

pub mod ui;

use {
    crate::ui::{AuthenticationState, PinEntry, State},
    clap::{ArgGroup, Parser},
    log::{error, info, warn},
    rsa::PublicKeyParts,
    ssh_agent::{
        agent::Agent,
        proto::{
            to_bytes, AddIdentity, EcDsaPublicKey, Identity, Message, PublicKey, RsaPublicKey,
            SignRequest, Signature, RSA_SHA2_256, RSA_SHA2_512,
        },
    },
    ssh_key::MPInt,
    std::{
        ops::DerefMut,
        path::PathBuf,
        str::FromStr,
        sync::{Arc, Mutex, MutexGuard},
        thread,
        time::{Duration, Instant},
    },
    thiserror::Error,
    x509::SubjectPublicKeyInfo,
    x509_certificate::DigestAlgorithm,
    yubikey::{
        certificate::PublicKeyInfo,
        piv::{AlgorithmId, SlotId},
        Certificate, Error as YkError, MgmKey, YubiKey,
    },
};

const PIN_PROMPT_TIMEOUT_SECONDS: u64 = 60;

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

/// Describes the needed authentication for an operation.
pub enum RequiredAuthentication {
    Pin,
    ManagementKey,
    ManagementKeyAndPin,
}

impl RequiredAuthentication {
    pub fn requires_pin(&self) -> bool {
        match self {
            Self::Pin | Self::ManagementKeyAndPin => true,
            Self::ManagementKey => false,
        }
    }

    pub fn requires_management_key(&self) -> bool {
        match self {
            Self::ManagementKey | Self::ManagementKeyAndPin => true,
            Self::Pin => false,
        }
    }
}

fn get_identity_from_slot(yk: &mut YubiKey, slot: SlotId) -> Result<Option<Identity>, Error> {
    let cert = match Certificate::read(yk, slot) {
        Ok(cert) => cert,
        Err(e) => {
            error!("failed to read certificate from YubiKey: {:?}", e);
            return Ok(None);
        }
    };

    let key = match cert.subject_pki() {
        PublicKeyInfo::Rsa { pubkey, .. } => {
            // SSH keys use MPInt encoding, unlike nearly every other crypto
            // format.
            let e = MPInt::from_positive_bytes(&pubkey.e().to_bytes_be())?;
            let n = MPInt::from_positive_bytes(&pubkey.n().to_bytes_be())?;

            PublicKey::Rsa(RsaPublicKey {
                e: e.as_bytes().to_vec(),
                n: n.as_bytes().to_vec(),
            })
        }
        // ECDSA keys aren't well tested. This may be buggy.
        PublicKeyInfo::EcP256(_) => {
            let q = MPInt::from_positive_bytes(&cert.subject_pki().public_key())?;

            PublicKey::EcDsa(EcDsaPublicKey {
                identifier: "ecdsa-sha2-nistp256".to_string(),
                q: q.as_bytes().to_vec(),
            })
        }
        PublicKeyInfo::EcP384(_) => {
            let q = MPInt::from_positive_bytes(&cert.subject_pki().public_key())?;

            PublicKey::EcDsa(EcDsaPublicKey {
                identifier: "ecdsa-sha2-nistp384".to_string(),
                q: q.as_bytes().to_vec(),
            })
        }
    };

    Ok(Some(Identity {
        pubkey_blob: to_bytes(&key)?,
        comment: cert.subject().to_string(),
    }))
}

struct SshAgent {
    yk: Arc<Mutex<Option<YubiKey>>>,
    slot: SlotId,
    state: Arc<Mutex<State>>,
}

impl SshAgent {
    fn get_state(&self) -> Result<MutexGuard<State>, Error> {
        self.state
            .lock()
            .map_err(|_| Error::Lock("failed to acquire state lock"))
    }

    /// Obtain an exclusive lock on the YubiKey.
    ///
    /// If a YubiKey is available, returns `Some`. Otherwise `None`.
    pub fn get_yk(&self) -> Result<MutexGuard<Option<YubiKey>>, Error> {
        let mut guard = self
            .yk
            .lock()
            .map_err(|_| Error::Lock("failed to acquire mutex on YubiKey"))?;

        // Perform a state check to make sure the hardware session is in a good
        // state and clear out existing connection if not.
        if let Some(yk) = guard.deref_mut() {
            match Certificate::read(yk, SlotId::Authentication) {
                Ok(_) => {
                    info!("found existing session; successfully performed PCSC state check");
                }
                Err(YkError::PcscError { .. }) => {
                    warn!("PCSC connection to YubiKey went away; resetting session");
                    guard.take();
                }
                Err(_) => {}
            }
        }

        if guard.is_none() {
            warn!("establishing new session with YubiKey");

            match YubiKey::open() {
                Ok(yk) => {
                    guard.replace(yk);
                }
                Err(e) => {
                    warn!("failed to open YubiKey: {}", e);
                }
            }
        }

        self.get_state()?.set_session_opened(guard.is_some());

        Ok(guard)
    }

    fn add_identity(&self, _identity: AddIdentity) -> Result<Message, Error> {
        warn!("agent does not support registering foreign identities / keys");

        Ok(Message::Failure)
    }

    fn resolve_identities(&self) -> Result<Vec<Identity>, Error> {
        let mut identities = vec![];

        let mut guard = self.get_yk()?;

        if let Some(yk) = guard.deref_mut() {
            if let Some(identity) = get_identity_from_slot(yk, self.slot)? {
                info!("returning YubiKey identity for identities request");
                identities.push(identity);
            }
        } else {
            warn!("request for identities but no YubiKey found; returning empty list");
        }

        Ok(identities)
    }

    fn get_identities(&self) -> Result<Message, Error> {
        // There's an apparent bug (at least on macOS) where PCSC interruption
        // can result in the YubiKey returning empty data for a populated slot.
        // To mitigate this, we automatically retry lookups if we get no
        // identities by purging the former YubiKey connection.
        let identities = self.resolve_identities()?;

        let identities = if identities.is_empty() {
            let try_again = {
                let mut yk = self.get_yk()?;

                if yk.is_some() {
                    warn!("no keys found during identities lookup; resetting YubiKey session and trying again");
                    yk.take();
                    self.get_state()?.set_session_opened(false);

                    true
                } else {
                    false
                }
            };

            if try_again {
                self.resolve_identities()?
            } else {
                identities
            }
        } else {
            identities
        };

        Ok(Message::IdentitiesAnswer(identities))
    }

    fn sign_request(&self, request: SignRequest) -> Result<Message, Error> {
        let mut guard = self.get_yk()?;

        let yk = if let Some(yk) = guard.deref_mut() {
            yk
        } else {
            warn!("cannot sign because YubiKey isn't connected");
            return Ok(Message::Failure);
        };

        let identity = if let Some(identity) = get_identity_from_slot(yk, self.slot)? {
            identity
        } else {
            warn!("failed to read certificate from YubiKey; cannot sign");
            return Ok(Message::Failure);
        };

        if identity.pubkey_blob != request.pubkey_blob {
            warn!("mismatch between sign request public key and YubiKey's public key; ignoring");
            return Ok(Message::Failure);
        }

        let yk_cert = Certificate::read(yk, self.slot)?;

        let algorithm_id = match yk_cert.subject_pki() {
            PublicKeyInfo::Rsa { pubkey, .. } => match pubkey.n().to_bytes_be().len() {
                128 => AlgorithmId::Rsa1024,
                256 => AlgorithmId::Rsa2048,
                v => {
                    error!(
                        "unable to determine RSA key type (this should not happen) ({})",
                        v
                    );
                    return Ok(Message::Failure);
                }
            },
            PublicKeyInfo::EcP256(_) => AlgorithmId::EccP256,
            PublicKeyInfo::EcP384(_) => AlgorithmId::EccP384,
        };

        let (digest_algorithm, algorithm_name) = match algorithm_id {
            AlgorithmId::Rsa1024 | AlgorithmId::Rsa2048 => {
                if request.flags & RSA_SHA2_512 != 0 {
                    (DigestAlgorithm::Sha512, "rsa-sha2-512")
                } else if request.flags & RSA_SHA2_256 != 0 {
                    (DigestAlgorithm::Sha256, "rsa-sha2-256")
                } else {
                    (DigestAlgorithm::Sha1, "ssh-rsa")
                }
            }
            AlgorithmId::EccP256 => (DigestAlgorithm::Sha256, "ecdsa-sha2"),
            AlgorithmId::EccP384 => (DigestAlgorithm::Sha384, "ecdsa-sha2"),
        };

        // We need to apply PKCS#1 padding when signing RSA.
        let digest = match algorithm_id {
            AlgorithmId::Rsa1024 => digest_algorithm.rsa_pkcs1_encode(&request.data, 1024 / 8)?,
            AlgorithmId::Rsa2048 => digest_algorithm.rsa_pkcs1_encode(&request.data, 2048 / 8)?,
            AlgorithmId::EccP256 | AlgorithmId::EccP384 => {
                digest_algorithm.digest_data(&request.data)
            }
        };

        let res = self.attempt_authenticated_operation(
            yk,
            |yk| {
                let signature = yubikey::piv::sign_data(yk, &digest, algorithm_id, self.slot)?;

                self.get_state()?.record_signing_operation();

                Ok(signature.to_vec())
            },
            RequiredAuthentication::Pin,
        );

        match res {
            Ok(signature) => {
                let signature = Signature {
                    algorithm: algorithm_name.to_string(),
                    blob: signature,
                };

                Ok(Message::SignResponse(to_bytes(&signature)?))
            }
            Err(e) => {
                error!("failed to obtain signature from YubiKey: {}", e);
                Ok(Message::Failure)
            }
        }
    }

    fn attempt_authenticated_operation<T>(
        &self,
        yk: &mut YubiKey,
        op: impl Fn(&mut YubiKey) -> Result<T, Error>,
        required_authentication: RequiredAuthentication,
    ) -> Result<T, Error> {
        const MAX_ATTEMPTS: u8 = 3;

        for attempt in 1..MAX_ATTEMPTS + 1 {
            match op(yk) {
                Ok(x) => {
                    self.get_state()?
                        .set_authentication(AuthenticationState::Authenticated);

                    return Ok(x);
                }
                Err(Error::YubiKey(YkError::AuthenticationError)) => {
                    {
                        let mut state = self.get_state()?;
                        state.set_authentication(AuthenticationState::Unauthenticated);
                        state.record_failed_operation();
                    }

                    // This was our last attempt. Give up now.
                    if attempt == MAX_ATTEMPTS {
                        return Err(Error::SmartcardFailedAuthentication);
                    }

                    warn!("device refused operation due to authentication error");

                    if required_authentication.requires_management_key() {
                        match yk.authenticate(MgmKey::default()) {
                            Ok(()) => {
                                warn!("management key authentication successful");
                            }
                            Err(e) => {
                                error!("management key authentication failure: {}", e);
                                continue;
                            }
                        }
                    }

                    if required_authentication.requires_pin() {
                        // We need to be careful about deadlock here, as the
                        // UI thread will continuously acquire the state lock
                        // to process interactions. So our lock holds need to be
                        // as short as possible.
                        {
                            self.get_state()?.request_pin()?;
                        }

                        let deadline =
                            Instant::now() + Duration::from_secs(PIN_PROMPT_TIMEOUT_SECONDS);

                        let pin;

                        loop {
                            // Need to bind to a local to avoid recursive state lock.
                            let entry = self.get_state()?.retrieve_pin();
                            if let Some(entry) = entry {
                                match entry {
                                    PinEntry::Pin(value) => {
                                        pin = Some(value);
                                    }
                                    PinEntry::Denied => {
                                        warn!("user denied PIN entry");
                                        let mut state = self.get_state()?;
                                        state.record_failed_operation();
                                        state.pin_rejected();
                                        return Err(Error::SmartcardFailedAuthentication);
                                    }
                                }

                                break;
                            }

                            if Instant::now() >= deadline {
                                warn!("reached maximum wait time for PIN; giving up");
                                return Err(Error::SmartcardFailedAuthentication);
                            }

                            thread::sleep(Duration::from_millis(25));
                        }

                        match yk.verify_pin(pin.unwrap().as_bytes()) {
                            Ok(()) => {
                                self.get_state()?.pin_accepted();
                                warn!("PIN verification successful");
                            }
                            Err(e) => {
                                error!("PIN verification failed: {}", e);
                                {
                                    let mut state = self.get_state()?;
                                    state.record_failed_operation();
                                    state.pin_rejected();
                                }

                                continue;
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Err(Error::SmartcardFailedAuthentication)
    }
}

impl Agent for SshAgent {
    type Error = Error;

    fn handle(&self, message: Message) -> Result<Message, Self::Error> {
        match message {
            Message::RequestIdentities => self.get_identities(),
            Message::SignRequest(request) => self.sign_request(request),
            Message::AddIdentity(identity) => self.add_identity(identity),
            _ => {
                info!("ignoring unhandled message type");
                Ok(Message::Success)
            }
        }
    }
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

    let agent = SshAgent {
        yk: Arc::new(Mutex::new(None)),
        slot,
        state: state.clone(),
    };

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
