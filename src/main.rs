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

use {
    clap::{ArgGroup, Parser},
    log::{error, info, warn},
    notify_rust::Notification,
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
    },
    thiserror::Error,
    x509::SubjectPublicKeyInfo,
    x509_certificate::{DigestAlgorithm, X509CertificateError},
    yubikey::{
        certificate::PublicKeyInfo,
        piv::{AlgorithmId, SlotId},
        Certificate, Error as YkError, MgmKey, YubiKey,
    },
    zeroize::Zeroizing,
};

#[derive(Debug, Error)]
enum Error {
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

/// A function that will attempt to resolve the PIN to unlock a YubiKey.
type PinCallback = fn() -> Result<Vec<u8>, Error>;

fn prompt_smartcard_pin() -> Result<Vec<u8>, Error> {
    Notification::new()
        .summary("YubiKey pin needed")
        .body("SSH is requesting you to unlock your YubiKey")
        .timeout(5000)
        .show()?;

    let pin = dialoguer::Password::new()
        .with_prompt("Please enter device PIN")
        .interact()?;

    Ok(pin.as_bytes().to_vec())
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

/// Attempts an operation that requires YubiKey authentication.
fn attempt_authenticated_operation<T>(
    yk: &mut YubiKey,
    op: impl Fn(&mut YubiKey) -> Result<T, Error>,
    required_authentication: RequiredAuthentication,
    get_device_pin: Option<&PinCallback>,
) -> Result<T, Error> {
    const MAX_ATTEMPTS: u8 = 3;

    for attempt in 1..MAX_ATTEMPTS + 1 {
        info!("attempt {}/{}", attempt, MAX_ATTEMPTS);

        match op(yk) {
            Ok(x) => {
                return Ok(x);
            }
            Err(Error::YubiKey(YkError::AuthenticationError)) => {
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
                    if let Some(pin_cb) = get_device_pin {
                        let pin = Zeroizing::new(pin_cb().map_err(|e| {
                            X509CertificateError::Other(format!(
                                "error retrieving device pin: {}",
                                e
                            ))
                        })?);

                        match yk.verify_pin(&pin) {
                            Ok(()) => {
                                warn!("pin verification successful");
                            }
                            Err(e) => {
                                error!("pin verification failure: {}", e);
                                continue;
                            }
                        }
                    } else {
                        warn!(
                            "unable to retrieve device pin; future attempts will fail; giving up"
                        );
                        return Err(Error::SmartcardFailedAuthentication);
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

/// Manages access to a global YubiKey instance.
struct GlobalYubiKey {
    yk: Arc<Mutex<Option<YubiKey>>>,
}

impl GlobalYubiKey {
    pub fn new() -> Self {
        Self {
            yk: Arc::new(Mutex::new(None)),
        }
    }

    /// Obtain an exclusive lock on the YubiKey.
    ///
    /// If a YubiKey is available, returns `Some`. Otherwise `None`.
    pub fn get(&self) -> Result<MutexGuard<Option<YubiKey>>, Error> {
        let mut guard = self
            .yk
            .lock()
            .map_err(|_| Error::Lock("failed to acquire mutex on YubiKey"))?;

        if guard.is_none() {
            match YubiKey::open() {
                Ok(yk) => {
                    guard.replace(yk);
                }
                Err(e) => {
                    warn!("failed to open YubiKey: {}", e);
                }
            }
        }

        Ok(guard)
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
    yk: GlobalYubiKey,
    slot: SlotId,
    pin_callback: Option<PinCallback>,
}

impl SshAgent {
    fn add_identity(&self, _identity: AddIdentity) -> Result<Message, Error> {
        warn!("agent does not support registering foreign identities / keys");

        Ok(Message::Failure)
    }

    fn get_identities(&self) -> Result<Message, Error> {
        let mut identities = vec![];

        let mut guard = self.yk.get()?;

        if let Some(yk) = guard.deref_mut() {
            if let Some(identity) = get_identity_from_slot(yk, self.slot)? {
                info!("returning YubiKey identity for identities request");
                identities.push(identity);
            }
        } else {
            warn!("request for identities but not YubiKey found; returning empty list");
        }

        Ok(Message::IdentitiesAnswer(identities))
    }

    fn sign_request(&self, request: SignRequest) -> Result<Message, Error> {
        let mut guard = self.yk.get()?;

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

        let res = attempt_authenticated_operation(
            yk,
            |yk| {
                let signature = ::yubikey::piv::sign_data(yk, &digest, algorithm_id, self.slot)?;

                Ok(signature.to_vec())
            },
            RequiredAuthentication::Pin,
            self.pin_callback.as_ref(),
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

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    let slot = SlotId::from_str(&cli.slot).expect("illegal slot value; try 9a");
    warn!("using slot {:?}", slot);

    let agent = SshAgent {
        yk: GlobalYubiKey::new(),
        slot,
        pin_callback: Some(prompt_smartcard_pin),
    };

    if let Some(path) = cli.socket {
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }

        warn!("To use this agent process:");
        warn!("export SSH_AUTH_SOCK={}", path.display());

        agent.run_unix(&path).expect("agent should exit cleanly");
    } else if let Some(address) = cli.tcp {
        agent.run_tcp(&address).expect("agent should exit cleanly");
    }
}
