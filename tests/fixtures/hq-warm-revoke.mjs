// One real HQ identity client in the dedicated account; issuer is loopback-only.
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
assert.equal(process.env.GITHUB_ACTIONS, 'true');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
assert.equal(userInfo().username, '_agent-bot-hq');
const [stage, thumb] = process.argv.slice(2);
const source = join(stage, 'hq-source');
const load = path => import(pathToFileURL(join(source, path)));
const [{ createMachineSigner }, { createEnrollment }, { createIdentityService }] = await Promise.all([
  load('hq/machine-device.mjs'), load('hq/enrollment.mjs'), load('hq/identity-service.mjs'),
]);
const issuer = JSON.parse(readFileSync(join(stage, 'hq-issuer.json'), 'utf8'));
const local = new URL(issuer.url);
assert.equal(local.protocol, 'http:');
assert.equal(local.hostname, '127.0.0.1');
const origin = 'https://agents.true-line.ai';
const requests = [];
const fetchImpl = (url, options) => {
  const target = new URL(url);
  assert.equal(target.origin, origin);
  assert.ok(['/.well-known/agent-bot-server-key', '/oauth/device_authorization', '/oauth/token', '/api/daemon/whoami'].includes(target.pathname));
  requests.push([options.method ?? 'GET', target.pathname]);
  return fetch(new URL(target.pathname + target.search, local), { ...options, redirect: 'error' });
};
const home = mkdtempSync('/private/tmp/hq-warm-revoke-');
const signer = createMachineSigner({ home, keysFor: () => [issuer.key], enrollment: device => createEnrollment({
  home, signer: device, server: origin, fetchImpl, sleep: () => delay(10),
}) });
const identity = createIdentityService({ server: origin, keySet: [issuer.key], fetchImpl, enrollment: signer.enrollment, custody: signer.custody });
try {
  assert.equal(await signer.deviceStatus(), 'unenrolled');
  assert.equal(signer.report().backend, 'machine');
  assert.equal(signer.report().thumbprint, thumb);
  assert.equal((await signer.enroll({ harnesses: ['codex'] })).pending, true);
  await signer.enrollment.settled();
  assert.equal(await signer.deviceStatus(), 'enrolled');
  const firstStart = requests.length;
  const first = await identity.call('GET', '/api/daemon/whoami');
  assert.equal(first.status, 200);
  assert.equal(first.body.device.id, signer.enrollmentProgress().device_id);
  assert.equal(identity.status().tokenCached, true);
  assert.deepEqual(requests.slice(firstStart), [['POST', '/oauth/token'], ['GET', '/api/daemon/whoami']]);
  const secondStart = requests.length;
  const second = await identity.call('GET', '/api/daemon/whoami');
  assert.equal(second.status, 200);
  assert.equal(second.body.device.id, first.body.device.id);
  assert.deepEqual(requests.slice(secondStart), [['GET', '/api/daemon/whoami']], 'second lookup must reuse the cached token');
  console.log('warm');
  const lines = createInterface({ input: process.stdin });
  let acknowledged = false;
  for await (const line of lines) {
    assert.equal(line, 'revoked');
    const before = requests.length;
    await assert.rejects(identity.call('GET', '/api/daemon/whoami'), { code: 'credential_unavailable' });
    assert.equal(requests.length, before, 'revoked lookup must not contact the issuer');
    assert.equal(identity.status().tokenCached, false);
    assert.equal(signer.report().backend, 'machine');
    assert.equal(signer.report().available, false);
    assert.equal(existsSync(join(home, 'signer/device-key.pem')), false);
    assert.equal(existsSync(join(home, 'signer/pin.json')), false);
    console.log('revoked');
    acknowledged = true;
    break;
  }
  assert.equal(acknowledged, true, 'revocation checkpoint was not received');
} finally { identity.close(); rmSync(home, { recursive: true, force: true }); }
