# YubiKey SSH Agent

This project defines an SSH Agent specifically tailored for use with
YubiKeys.

The canonical home for this project is
https://github.com/indygreg/yubikey-ssh-agent.

## Usage

First, start up the agent:

    $ yubikey-ssh-agent --socket /tmp/yubikey-ssh.sock

Then, tell SSH how to use it:

    $ export SSH_AUTH_SOCK=/tmp/yubikey-ssh.sock

Then perform an SSH operation needing the private key on your YubiKey:

    $ ssh git@github.com

## Features

The `yubikey-ssh-agent` process provides a minimal SSH agent daemon
that interfaces directly with attached YubiKeys to service requests
for public key lookups and cryptographic signing operations.

The process provides a minimal GUI displaying current state and
provides a mechanism for inputting the PIN to unlock the YubiKey.

System notifications are displayed when the YubiKey needs to be
unlocked by entering a PIN.

## Advantages Over Normal SSH Agent

This tool was born because out of the author's frustration with the user
experience when using YubiKeys with OpenSSH using the default OpenSSH
agent (`ssh-agent`) and `libykcs11`.

When you use the default OpenSSH SSH agent + `libykcs11`:

1. `ssh-agent` spawns a `ssh-pkcs11-helper` process.
2. `ssh-pkcs11-helper` loads `libykcs11.{so,dylib,dll}`.
3. When `ssh-agent` receives a message requesting interfacing with the
   YubiKey, it calls into APIs in `libykcs11`, which speaks to the
   YubiKey.
4. Results from `libykcs11` are relayed back to `ssh`.

A common problem is that `libykcs11` will lose contact with the YubiKey.
What happens in this scenario is `ssh-agent` thinks that no YubiKey keys
are available and tells `ssh` there are no keys. `ssh` summarily tries
to authenticate without knowledge of the YubiKey keys. And this often
fails with a `Permission denied` message because the client didn't
actually present any public keys! Or a variant of this is that `ssh-agent`
advertises the YubiKey-hosted key but when it attempts to sign the
signing operation fails because teh YubiKey is locked and this also
results in a nebulous `Permission denied`.

This SSH agent has the luxury of being domain specific and can be
highly opinionated about its workings.

This SSH agent makes the assumption that the YubiKey is the only
thing providing SSH keys. Therefore, when there is a request for available
keys or a signature request, it can be very vocal about raising an error
(through its own GUI or OS notifications) when user interaction is needed.
For example, if SSH wants to perform a cryptographic signature but the
YubiKey is locked, this agent will show you a system notification that
the YubiKey PIN needs to be entered and the SSH agent will wait for you
to unlock the YubiKey before failing the SSH attempt.

## State of Project

This project is still very alpha. The graphical UI in particular is
very crude and in need of a lot of work.

Please file issues or pull requests to discuss improvements!
