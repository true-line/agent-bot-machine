// Runs as the hosted role. Only the HTTP peer is a fixture. HQ discovers its
// real role, pinned Machine, socket and device-signing provider normally.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { fakeIdentityService } from './hq/tests/identity-service-fixture.mjs';

const owner = userInfo();
assert.equal(process.env.GITHUB_ACTIONS, 'true');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
assert.equal(process.platform, 'darwin');
assert.equal(owner.username, '_agent-bot-hq');
assert.ok(owner.uid >= 300 && owner.uid <= 399 && owner.gid === owner.uid && process.geteuid() === owner.uid);
assert.ok(['/var/agent-bot-hq', '/private/var/agent-bot-hq'].includes(owner.homedir));
const [thumb] = process.argv.slice(2);
assert.match(thumb, /^[A-Za-z0-9_-]{43}$/);
const dir = mkdtempSync('/private/tmp/hq-device-');
const cli = fileURLToPath(new URL('./hq/hq/main.mjs', import.meta.url));
const preload = fileURLToPath(new URL('./hq/tests/fixtures/paired-process-ports.mjs', import.meta.url));
const issuer = await fakeIdentityService({ issuer: 'https://agents.true-line.ai' });
assert.equal(new URL(issuer.url).hostname, '127.0.0.1');
const env = { PATH: '/usr/bin:/bin', HOME: owner.homedir };
const exec = promisify(execFile);
let daemon, daemonExit, firstJti;
const call = (...args) => exec(process.execPath, [cli, ...args, '--home', dir], { env, encoding: 'utf8', timeout: 15_000 });
const status = async () => JSON.parse((await call('status', '--json')).stdout);
async function until(check) {
  for (let attempt = 0; attempt < 150; attempt++) {
    if (check()) return;
    await delay(50);
  }
  throw new Error('packaged HQ fixture deadline');
}
async function start() {
  daemon = spawn(process.execPath, ['--import', preload, cli, 'run', '--home', dir], {
    env: { ...env, HQ_TEST_REGISTERED_LAYOUT: '1', HQ_TEST_ISSUER: issuer.url }, stdio: 'ignore',
  });
  daemonExit = new Promise((resolve, reject) => { daemon.once('error', reject); daemon.once('close', resolve); });
  await Promise.race([until(() => existsSync(join(dir, 'control.sock'))), daemonExit.then(() => { throw new Error('packaged HQ exited before serving'); })]);
  const s = await status();
  assert.equal(s.hq.account, owner.username);
  assert.equal(s.profile, 'managed-cooperative');
  assert.equal(s.hq.signer.backend, 'machine');
  return s.hq.signer;
}
async function stop() {
  if (!daemon) return;
  daemon.kill('SIGTERM');
  const deadline = setTimeout(() => daemon.kill('SIGKILL'), 15_000);
  try { assert.equal(await daemonExit, 0); }
  finally { clearTimeout(deadline); daemon = undefined; }
}
async function signedGrant() {
  const count = issuer.state.grants.size;
  const denied = assert.rejects(call('enroll', '--harness', 'codex'), error => error.code === 1 && /the owner denied this device/.test(error.stderr));
  await Promise.race([until(() => issuer.state.grants.size === count + 1), denied]);
  // The loopback issuer has verified the actual enrollment proof. Refuse its
  // grant before any device binding, access token or credential can be issued.
  issuer.decide('denied');
  await denied;
  const grant = [...issuer.state.grants.values()].at(-1);
  assert.equal(grant.jkt, thumb);
  assert.equal(grant.form.key_storage, 'hardware');
  assert.equal(issuer.state.devices.length, 0);
  const claims = JSON.parse(Buffer.from(grant.form.proof.split('.')[1], 'base64url'));
  assert.match(claims.jti, /^[A-Za-z0-9_-]{22}$/);
  return claims.jti;
}
async function refused(reason) {
  const requests = issuer.state.requests.length;
  await assert.rejects(call('enroll', '--harness', 'codex'), error => {
    assert.equal(error.code, 1);
    const r = JSON.parse(error.stderr);
    assert.equal(r.error, 'credential_unavailable');
    assert.match(r.explanation, reason);
    return true;
  });
  const { hq } = await status();
  assert.equal(hq.signer.backend, 'machine');
  assert.equal(hq.signer.available, false);
  assert.match(hq.signer.reason, reason);
  assert.equal(issuer.state.requests.length, requests);
}
try {
  assert.equal((await start()).thumbprint, thumb);
  console.log('ready');
  const phases = ['prove', 'outage', 'recovered', 'revoked', 'stop'];
  const lines = createInterface({ input: process.stdin });
  for await (const phase of lines) {
    assert.equal(phase, phases.shift());
    if (phase === 'prove') firstJti = await signedGrant();
    if (phase === 'outage') {
      const offline = /could not connect to the paired Machine/;
      await refused(offline);
      // Restart while Machine is still stopped to exercise initial provider selection.
      const requests = issuer.state.requests.length;
      await stop();
      const signer = await start();
      assert.equal(signer.available, false);
      assert.match(signer.reason, offline);
      await refused(offline);
      assert.equal(issuer.state.requests.length, requests);
    }
    if (phase === 'recovered') assert.notEqual(await signedGrant(), firstJti);
    if (phase === 'revoked') {
      await refused(/MM_DAEMON_PEER_REFUSED/);
      await stop();
      assert.equal((await start()).available, false);
      await refused(/MM_DAEMON_PEER_REFUSED/);
    }
    if (phase === 'stop') break;
    assert.equal(existsSync(join(dir, 'signer/device-key.pem')), false);
    assert.equal(existsSync(join(dir, 'signer/pin.json')), false);
    console.log(phase);
  }
  assert.equal(phases.length, 0, 'packaged HQ fixture ended early');
} finally {
  try { await stop(); } finally {
    await issuer.close();
    rmSync(dir, { recursive: true, force: true });
  }
}
