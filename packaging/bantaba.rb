# Homebrew formula TEMPLATE for the `bantabad` daemon.
#
# The URLs are wired to kortiene/bantaba, but each sha256 below is a placeholder.
# This formula is unusable until a first `v*` release with attached tarballs
# exists and the release sha256 values are copied in. See packaging/README.md.
#
# This belongs in a tap, not homebrew-core: publish it as
#   kortiene/homebrew-bantaba  (repo `homebrew-bantaba`, file `Formula/bantaba.rb`)
# then users install with:
#   brew install kortiene/bantaba/bantaba
#
# To fill in per release:
#   1. Set `version` to the release number (no leading "v").
#   2. Replace each REPLACE_WITH_*_SHA256 with the sha256 of the matching
#      tarball. The release workflow uploads a `<asset>.sha256` sidecar next to
#      every archive -- copy those values here.
class Bantaba < Formula
  desc "Bantaba peer-to-peer daemon (bantabad): serves the Bantaba UI over a local WebSocket"
  homepage "https://github.com/kortiene/bantaba"
  version "0.1.0"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/kortiene/bantaba/releases/download/v#{version}/bantabad-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_AARCH64_MACOS_SHA256"
    end
    on_intel do
      url "https://github.com/kortiene/bantaba/releases/download/v#{version}/bantabad-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_X86_64_MACOS_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/kortiene/bantaba/releases/download/v#{version}/bantabad-v#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "REPLACE_WITH_AARCH64_LINUX_SHA256"
    end
    on_intel do
      url "https://github.com/kortiene/bantaba/releases/download/v#{version}/bantabad-v#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "REPLACE_WITH_X86_64_LINUX_SHA256"
    end
  end

  def install
    bin.install "bantabad"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bantabad --version")
  end
end
