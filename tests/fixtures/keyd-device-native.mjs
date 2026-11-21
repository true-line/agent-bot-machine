// Hosted release-executable acceptance. The synthetic Machine authorizes a
// typed request; verification uses only the device public key and Node crypto.
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { existsSync, mkdirSync, rmSync, rmdirSync, writeFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { dirname, join } from 'node:path';
import { exerciseNativeChannel } from './keyd-device-channel.mjs';

function requireCheck(condition) {
  if (!condition) throw new Error('native keyd acceptance failed');
}

async function exercise() {
  requireCheck(process.platform === 'darwin' && process.arch === 'arm64' &&
    process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted' &&
    process.env.MM_KEYD_CUSTODY_TEST === '1');
  const [helper, role] = process.argv.slice(2);
  const uid = Number(role);
  requireCheck(helper?.startsWith('/') && Number.isSafeInteger(uid) && uid > 0 && uid !== process.getuid());
  const config = join(userInfo().homedir, '.config');
  const state = join(config, 'agent-machine');
  const madeConfig = !existsSync(config);
  if (madeConfig) mkdirSync(config, { mode: 0o700 });
  // mkdir is exclusive and fails on any pre-existing directory or symlink.
  mkdirSync(state, { mode: 0o700 });
  try {
    // Starting keyd also records Machine use in the prefix owner's registered
    // home. Run it only after this fixture has exclusively acquired that state.
    const stage = dirname(helper);
    requireCheck(spawnSync('python3', [join(stage, 'mcp-handshake.py'), helper, stage], { stdio: 'inherit' }).status === 0);
    const machine = generateKeyPairSync('ed25519');
    const hq = generateKeyPairSync('ed25519');
    const owner = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    const raw = (pub) => Buffer.from(pub.export({ format: 'jwk' }).x, 'base64url');
    const ownerPoint = Buffer.concat([Buffer.from([4]), Buffer.from(owner.x, 'base64url'), Buffer.from(owner.y, 'base64url')]);
    const epoch = randomBytes(32).toString('hex');
    const put = (file, bytes) => writeFileSync(join(state, file), bytes, { mode: 0o600, flag: 'wx' });
    put('daemon.pub', raw(machine.publicKey));
    put('owner-pair.lock', '');
    put('owner-pair.json', JSON.stringify({ owner: ownerPoint.toString('base64'), machine: raw(machine.publicKey).toString('hex'),
      hq: raw(hq.publicKey).toString('hex'), uid, hq_epoch: epoch }));
    mkdirSync(join(state, 'peers'), { mode: 0o700 });
    const child = (verb, req) => spawnSync(helper, [verb], {
      input: req ? JSON.stringify(req) : '', encoding: 'utf8', timeout: 15_000, maxBuffer: 8192,
      env: { HOME: userInfo().homedir, PATH: '/usr/bin:/bin' },
    });
    const request = (option) => {
      const machine_pub = raw(machine.publicKey).toString('base64'), hq_pub = raw(hq.publicKey).toString('base64');
      const req_nonce = randomBytes(16).toString('base64url'), timestamp = Math.floor(Date.now() / 1000);
      const bytes = ['agent-bot-machine/keyd-hq-device/v1', machine_pub, hq_pub, uid, req_nonce, timestamp, option,
        '', '', '', 'hq_epoch', epoch].join('\n');
      return { option, machine_pub, hq_pub, hq_uid: uid, hq_epoch: epoch, req_nonce, timestamp,
        signature: sign(null, Buffer.from(bytes), machine.privateKey).toString('base64') };
    };
    const refused = (r) => requireCheck(r.status === 1 && r.stdout === '' && r.stderr.trim() === 'agent-bot-keyd: device custody unavailable');
    refused(child('hq-device', request('identity')));
    const init = child('hq-device-init');
    requireCheck(init.status === 0 && init.stdout === '');
    refused(child('hq-device-init'));
    const ok = (req) => {
      const r = child('hq-device', req);
      requireCheck(r.status === 0);
      return JSON.parse(r.stdout);
    };
    const id = ok(request('identity'));
    const { crv, kty, x, y } = id.jwk;
    const thumb = createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest('base64url');
    requireCheck(crv === 'P-256' && kty === 'EC' && id.key_storage === 'hardware' &&
      id.generation === 1 && thumb === id.thumbprint);
    const enroll = request('enrollment-proof');
    const proof = ok(enroll);
    const [header, claims, signature] = proof.proof.split('.');
    const hdr = JSON.parse(Buffer.from(header, 'base64url')), payload = JSON.parse(Buffer.from(claims, 'base64url'));
    requireCheck(hdr.alg === 'ES256' && hdr.typ === 'ab-enroll+jwt' && hdr.jwk.x === x && hdr.jwk.y === y &&
      payload.aud === 'https://agents.true-line.ai/oauth/device_authorization' &&
      verify('sha256', Buffer.from(header + '.' + claims), { key: createPublicKey({ key: id.jwk, format: 'jwk' }),
        dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')));
    refused(child('hq-device', enroll));
    requireCheck(ok(request('identity')).thumbprint === thumb);
    await exerciseNativeChannel(dirname(helper), machine, hq, epoch, thumb);
    refused(child('hq-device', request('identity')));
  } finally {
    rmSync(state, { recursive: true, force: true });
    if (madeConfig) rmdirSync(config);
  }
}

try {
  await exercise();
  console.log('PASS native admin keyd initialization, independent ES256 verification, restart and revocation');
} catch {
  console.error('FAIL native admin keyd process or custody check');
  process.exitCode = 1;
}
