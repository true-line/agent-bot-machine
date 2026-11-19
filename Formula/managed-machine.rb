# typed: false
# frozen_string_literal: true

# Managed-machine Homebrew formula.
# Self-tap: brew tap true-line/agent-bot-machine https://github.com/true-line/agent-bot-machine.git
# Then: brew install managed-machine
#
# The public formula installs only the Machine release and its orchestration files.
#
# Prepare the reviewed release branch with scripts/release prepare vX.Y.Z.
class ManagedMachine < Formula
  desc "Fresh-Mac bootstrap and fleet setup orchestration"
  homepage "https://github.com/true-line/agent-bot-machine"
  url "https://github.com/true-line/agent-bot-machine.git",
      using: :git,
      tag:   "v0.12.1"
  version "0.12.1"
  license "MIT"

  depends_on arch: :arm64
  depends_on macos: :sequoia

  # Prebuilt portable Go core binary for darwin/arm64 (S6 R04, S8 D3).
  # Installed as bin/managed-machine; legacy Bash tree staged under libexec/legacy.
  resource "core" do
    url "https://github.com/true-line/agent-bot-machine/releases/download/v0.12.1/managed-machine_0.12.1_darwin_arm64.tar.gz"
    sha256 "31223ec824721b226a6b7f3049dc19fc971b4e359ee729f0db79f3920314bc4e"
  end

  def install
    libexec.mkpath
    libexec.install "install.sh"
    legacy = libexec / "legacy"
    legacy.mkpath

    # Install legacy macOS Bash orchestration files into libexec/legacy.
    (legacy / "bin").install "legacy/bin/managed-machine"
    legacy.install Dir["legacy/setup-*"]
    legacy.install "legacy/lib"
    (legacy / "scripts").install Dir["legacy/scripts/*"]
    (legacy / "git-hooks").install Dir["legacy/git-hooks/*"]

    # Older installations re-exec this path after a Homebrew upgrade.
    (libexec / "scripts").mkpath
    (libexec / "scripts/update").write <<~SH
      #!/usr/bin/env bash
      exec "$(dirname "$0")/../legacy/scripts/update" "$@"
    SH
    chmod 0755, libexec / "scripts/update"

    # Install the prebuilt Go core binary directly as bin/managed-machine
    # (S8 P01 inversion: the Go core is the primary entry point; agent-machine
    # is the command alias).
    bin.mkpath
    resource("core").stage do
      bin.install "managed-machine"
      chmod 0755, bin / "managed-machine"
      bin.install "agent-bot-keyd"
      chmod 0700, bin / "agent-bot-keyd"
    end
    bin.install_symlink "managed-machine" => "agent-machine"

    # ENG-0055 skill bundle: `managed-machine --version` and `skill path`
    # resolve VERSION, skills/managed-machine and RELEASE_COMMIT from libexec.
    if File.exist?("VERSION")
      cp "VERSION", legacy / "VERSION"
      libexec.install "VERSION"
      (libexec / "skills").install "skills/managed-machine"
      commit = Utils.safe_popen_read("git", "-C", buildpath, "rev-parse", "HEAD").strip
      (libexec / "RELEASE_COMMIT").write "#{commit.match?(/\A\h{40}\z/) ? commit : "unknown"}\n"
    end
  end

  # Older Homebrew has either no permissions step or only a recursive one.
  if respond_to?(:post_install_steps) &&
     Homebrew::InstallSteps::DSL.method_defined?(:set_permissions) &&
     Homebrew::InstallSteps::DSL.instance_method(:set_permissions).parameters.include?([:key, :recursive])
    post_install_steps do
      set_permissions "bin/agent-bot-keyd", "0700", base: :prefix, recursive: false
    end
  else
    def post_install
      chmod 0700, bin / "agent-bot-keyd"
    end
  end

  test do
    assert_predicate libexec/"install.sh", :executable?
    help_output = shell_output("#{bin}/managed-machine --help")
    assert_match "managed-machine", help_output
    assert_match "status", help_output
    assert_match "[legacy] adopt", help_output
    assert_equal 0700, (bin/"agent-bot-keyd").stat.mode & 07777
    assert_predicate libexec/"legacy/setup-hostname", :executable?
    assert_predicate libexec/"scripts/update", :executable?

    # The failure path resolves libexec/legacy through the core exec seam and
    # must name the bad input.
    invalid = shell_output("#{bin}/managed-machine setup no-such-setup 2>&1", 1)
    assert_match "unknown setup name", invalid

    assert_equal version.to_s, shell_output("#{bin}/managed-machine --version").strip
    assert_equal version.to_s, shell_output("#{bin}/agent-machine --version").strip
    shell_output("#{bin}/managed-machine version")
  end
end
