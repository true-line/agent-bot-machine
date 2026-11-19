# Public, synthetic metadata only. No installed service, root account or signing identity.
require 'tmpdir'
require 'fileutils'
load File.expand_path('../../scripts/standalone-hq-signing', __dir__)

class FixtureDeclaration < StandaloneHQSigning
  attr_accessor :home, :manifest, :other_home
  def locally_registered_homes
    [other_home]
  end
  def registered_home(_uid)
    home
  end
  def role_identity
    [331, '12345678-1234-4321-8765-123456789ABC', home, Process.gid]
  end
  def check_machine(home)
    pending = File.join(@directory, PENDING)
    raise 'missing pending marker during final inventory' unless File.file?(pending)
    super
  end
  def installer_manifest
    manifest
  end
  def verify_signature(_helper)
    # The fixture is plain text. The production invocation uses codesign.
  end
end

def refused(reason)
  begin
    yield
  rescue RuntimeError => e
    raise unless e.message.include?(reason)
    return
  end
  raise "expected refusal: #{reason}"
end

Dir.mktmpdir('standalone-machine') do |base|
  library = File.join(base, 'Library')
  prefix = File.join(base, 'homebrew')
  home = File.join(base, 'role')
  dir = File.join(library, 'Application Support', StandaloneHQSigning::PRODUCT, 'standalone')
  FileUtils.mkdir_p([dir, home, prefix])
  helper = File.join(dir, 'hq-signer')
  File.write(helper, 'independently pinned fixture helper')
  File.chmod(0555, helper)
  tool = FixtureDeclaration.new(library: library, prefixes: [prefix], uid: Process.uid)
  tool.home = home
  tool.other_home = File.join(base, "former-prefix-owner")
  FileUtils.mkdir_p(tool.other_home)
  qualified_digest = Digest::SHA256.hexdigest('independently pinned fixture helper')
  tool.manifest = File.join(base, 'reviewed-fixture-release.json')
  release = {schema: 'agent-bot-hq/standalone-helper-release/v1', hq_source: '2' * 40, helper_sha256: qualified_digest}
  File.write(tool.manifest, JSON.generate(release))
  active = File.join(dir, StandaloneHQSigning::ACTIVE)
  retired = File.join(dir, StandaloneHQSigning::RETIRED)
  # Absent Homebrew executable does not erase a retained pairing.
  history = File.join(home, '.config/agent-machine')
  FileUtils.mkdir_p(history)
  refused('existing Machine account state') { tool.operate(:declare) }
  Dir.rmdir(history)
  old = File.join(tool.other_home, ".config/agent-machine")
  FileUtils.mkdir_p(old)
  refused("existing Machine account state") { tool.operate(:declare) }
  Dir.rmdir(old)
  FileUtils.mkdir_p(File.join(prefix, 'bin'))
  binary = File.join(prefix, 'bin/managed-machine')
  File.write(binary, 'public fixture')
  refused('standard Machine installation') { tool.operate(:declare) }
  File.unlink(binary)
  tool.operate(:declare)
  gate = File.join(dir, StandaloneHQSigning::GATE)
  raise unless File.stat(gate).mode & 0777 == 0640
  expected = "agent-bot-hq/standalone-signing/v1\nrole=_agent-bot-hq\nuid=331\nuuid=12345678-1234-4321-8765-123456789ABC\nno-custom-machine-installation=true\nhelper-sha256=#{qualified_digest}\n"
  raise unless File.binread(active) == expected && (File.stat(active).mode & 0777) == 0644
  initial_inode = File.stat(active).ino
  tool.operate(:declare)
  raise unless File.stat(active).ino == initial_inode
  File.write(tool.manifest, JSON.generate(release.merge(helper_sha256: nil)))
  refused('does not qualify') { tool.operate(:declare) }
  File.write(tool.manifest, JSON.generate(release.merge(helper_sha256: '0' * 64)))
  refused('differs from the reviewed release') { tool.operate(:declare) }
  # Another process is required: POSIX record locks belong to a process.
  rd, ready = IO.pipe
  release, wr = IO.pipe
  child = fork do
    rd.close
    wr.close
    File.open(gate, File::RDONLY | File::NOFOLLOW) do |f|
      f.fcntl(Fcntl::F_SETLK, [0, 0, 0, Fcntl::F_RDLCK, IO::SEEK_SET].pack('qqiss'))
      ready.write('1')
      ready.close
      release.read(1)
    end
    exit! 0
  end
  ready.close
  release.close
  begin
    raise unless rd.read(1) == '1'
    refused('draining') { tool.operate(:retire) }
    raise unless File.exist?(active) && File.binread(retired) == StandaloneHQSigning::TOMBSTONE
  ensure
    wr.close
    rd.close
    Process.wait(child)
  end
  tool.operate(:retire)
  raise if File.exist?(active)
  raise unless File.binread(retired) == StandaloneHQSigning::TOMBSTONE
  tool.operate(:retire)
  refused('permanently retired') { tool.operate(:declare) }
end
