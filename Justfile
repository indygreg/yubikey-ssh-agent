default:
  cargo build

exe_suffix := if os() == "windows" { ".exe" } else { "" }

macosx_deployment_target := if os() == "macos" {
  if arch() == "arm" {
    "11.0"
  } else {
    "10.9"
  }
} else {
  ""
}

actions-bootstrap-rust-linux:
  sudo apt install -y --no-install-recommends libpcsclite-dev musl-tools
  sudo apt install -y libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libspeechd-dev libxkbcommon-dev libssl-dev

actions-bootstrap-rust-macos:

actions-build-exe bin triple:
  export MACOSX_DEPLOYMENT_TARGET={{macosx_deployment_target}}
  cargo build --release --bin {{bin}} --target {{triple}}
  mkdir upload
  cp target/{{triple}}/release/{{bin}}{{exe_suffix}} upload/{{bin}}{{exe_suffix}}

actions-macos-universal exe:
  mkdir -p uploads
  lipo {{exe}}-x86-64/{{exe}} {{exe}}-aarch64/{{exe}} -create -output uploads/{{exe}}
  chmod +x uploads/{{exe}}
  lipo uploads/{{exe}} -info

macos-universal:
  MACOSX_DEPLOYMENT_TARGET=10.9 cargo build --release --target x86_64-apple-darwin
  MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --target aarch64-apple-darwin
  rm -rf dist/macos-universal
  mkdir -p dist/macos-universal
  lipo target/x86_64-apple-darwin/release/yubikey-ssh-agent target/aarch64-apple-darwin/release/yubikey-ssh-agent -create -output dist/macos-universal/yubikey-ssh-agent
  chmod +x dist/macos-universal/yubikey-ssh-agent

create-zip-macos: macos-universal
  rm -rf dist/zip
  mkdir -p dist/zip/yubikey-ssh-agent
  rcodesign sign --smartcard-slot 9c --code-signature-flags runtime dist/macos-universal/yubikey-ssh-agent dist/zip/yubikey-ssh-agent/yubikey-ssh-agent
  chmod +x dist/zip/yubikey-ssh-agent/yubikey-ssh-agent
  cp LICENSE dist/zip/yubikey-ssh-agent/
  (cd dist/zip && zip -r yubikey-ssh-agent-macos.zip yubikey-ssh-agent)

create-bundle: macos-universal
  rm -rf dist/bundle.stage/Contents/MacOS
  cp dist/macos-universal/yubikey-ssh-agent/Contents/MacOS/yubikey-ssh-agent
  cp Info.plist dist/bundle.stage/Contents/Info.plist
  mkdir dist/bundle.unsigned
  mv dist/bundle.stage dist/bundle.unsigned/YubiKey\ SSH\ Agent.app
  rcodesign sign --smartcard-slot 9c --code-signature-flags runtime dist/bundle.unsigned/YubiKey\ SSH\ Agent.app dist/YubiKey\ SSH\ Agent.app
