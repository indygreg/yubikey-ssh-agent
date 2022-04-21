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
