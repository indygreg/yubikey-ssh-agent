# Documentation: https://docs.brew.sh/Formula-Cookbook
#                https://rubydoc.brew.sh/Formula
# PLEASE REMOVE ALL GENERATED COMMENTS BEFORE SUBMITTING YOUR PULL REQUEST!
class YubikeySshAgent < Formula
  desc "An opinionated SSH agent for YubiKeys"
  homepage "https://github.com/indygreg/yubikey-ssh-agent"
  url "https://github.com/indygreg/yubikey-ssh-agent/releases/download/0.0.1/yubikey-ssh-agent-macos.zip"
  sha256 "9e5f42cc0207755dfaa23687d99f9d9f66344612abada522b126a0decf1640ea"
  license "MPL-2.0"

  depends_on "rust" => :build
  depends_on "just" => :build

  def install
    just install
  end

  test do
    # TODO
  end
end
