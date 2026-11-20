// Disposable native acceptance. The dedicated role signs the Unix request.
// The runner acts as the offline issuer, outside the role's account.
import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { once } from 'node:events';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const origin = 'https://agents.true-line.ai';
const role = '_agent-bot-hq';
const kid = 'native-fixture';
const receiptFields = ['receipt_body', 'receipt_jti', 'receipt_kid', 'receipt_signature'];
const purposes = new Map([
  ['enrollment-proof', []], ['bind-enrollment', receiptFields], ['access-assertion', []],
  ['bind-access', receiptFields], ['whoami', ['session']],
]);
const digest = (data, encoding) => createHash('sha256').update(data).digest(encoding);
const jwkID = ({ crv, kty, x, y }) => digest(JSON.stringify({ crv, kty, x, y }), 'base64url');

function check(condition, phase) {
  if (!condition) throw new Error('hosted self-lookup failed: ' + phase);
}

function exactFields(value, names) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === names.length && names.every(k => Object.hasOwn(value, k));
}

function hosted() {
  check(process.platform === 'darwin' && process.arch === 'arm64' && process.getuid() > 0
    && process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted'
    && process.env.MM_KEYD_CUSTODY_TEST === '1', 'hosted runner required');
}

function privateIssuerDir(dir) {
  const stat = lstatSync(dir);
  check(userInfo().username !== role && stat.isDirectory() && stat.uid === process.getuid()
    && (stat.mode & 0o7777) === 0o700, 'private issuer directory');
}

export function createTestIssuer(directory) {
  hosted();
  privateIssuerDir(directory);
  const key = generateKeyPairSync('ed25519');
  const x = key.publicKey.export({ format: 'jwk' }).x;
  const date = offset => new Date(Date.now() + offset).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const pin = { kid, x, status: 'active', notBefore: date(-3600_000), notAfter: date(86400_000) };
  writeFileSync(join(directory, 'issuer.key'), key.privateKey.export({ type: 'pkcs8', format: 'der' }), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(directory, 'server-keys.json'), JSON.stringify({ server: origin, keys: [pin] }), { flag: 'wx', mode: 0o600 });
}

function receipt(issuer, body, jti) {
  const bytes = Buffer.from(JSON.stringify(body));
  const signed = Buffer.from(['agent-bot-sig-v1', '200', digest(bytes, 'hex'), jti].join('\n'));
  return { receipt_body: bytes.toString('base64url'), receipt_jti: jti, receipt_kid: kid,
    receipt_signature: sign(null, signed, issuer).toString('base64url') };
}

function verifyJWS(compact, publicKey, typ) {
  const parts = compact.split('.');
  check(parts.length === 3 && parts.every(s => s && Buffer.from(s, 'base64url').toString('base64url') === s), 'compact encoding');
  const [header, claims] = parts.slice(0, 2).map(s => JSON.parse(Buffer.from(s, 'base64url')));
  const carriesKey = typ !== 'JWT';
  check(exactFields(header, carriesKey ? ['alg', 'typ', 'jwk'] : ['alg', 'typ'])
    && header.alg === 'ES256' && header.typ === typ, 'proof header');
  if (carriesKey) check(exactFields(header.jwk, ['kty', 'crv', 'x', 'y']) && jwkID(header.jwk) === jwkID(publicKey), 'proof public key');
  check(publicKey.kty === 'EC' && publicKey.crv === 'P-256' && verify('sha256', Buffer.from(parts.slice(0, 2).join('.')),
    { key: createPublicKey({ key: publicKey, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2], 'base64url')), 'native signature');
  check(Number.isSafeInteger(claims.iat) && Math.abs(Date.now() / 1000 - claims.iat) <= 60
    && typeof claims.jti === 'string' && /^[A-Za-z0-9_-]{22}$/.test(claims.jti)
    && Buffer.from(claims.jti, 'base64url').toString('base64url') === claims.jti, 'proof freshness');
  return claims;
}

// One role process per request means the actual kernel peer and persisted HQ
// channel key are used both before and after the Machine process restarts.
async function roleRequest(socket, epoch, option, fields) {
  hosted();
  const account = userInfo();
  check(account.username === role && /^[a-f0-9]{64}$/.test(epoch), 'dedicated role');
  const extra = purposes.get(option);
  check(extra && exactFields(fields, extra) && extra.every(k => typeof fields[k] === 'string' && !/[\r\n]/.test(fields[k])), 'request fields');
  const dir = join(account.homedir, '.config', 'agent-machine');
  const rawPublic = readFileSync(join(dir, 'client.pub'));
  const client = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), readFileSync(join(dir, 'client.key'))]), format: 'der', type: 'pkcs8' });
  check(createPublicKey(client).export({ format: 'der', type: 'spki' }).subarray(-32).equals(rawPublic), 'HQ channel public key');
  const machine = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), readFileSync(join(dir, 'daemon.pub'))]), format: 'der', type: 'spki' });
  const nonce = randomBytes(16).toString('base64url'), timestamp = Math.floor(Date.now() / 1000);
  const parts = ['hq-device', '', option, '', '', '', '', '', timestamp, nonce, 'hq_epoch', epoch];
  for (const key of extra) parts.push(key, fields[key]);
  const frame = { verb: 'hq-device', option, hq_epoch: epoch, ...fields, timestamp, nonce, public_key: rawPublic.toString('base64'),
    signature: sign(null, Buffer.from(parts.join('\n')), client).toString('base64') };
  const stream = createConnection(socket);
  stream.setTimeout(6000, () => stream.destroy(new Error('fixture socket timeout')));
  try {
    try { await once(stream, 'connect'); } catch (error) {
      if (['ENOENT', 'ECONNREFUSED'].includes(error.code)) return { offline: true };
      throw error;
    }
    stream.write(JSON.stringify(frame) + '\n');
    let line = '';
    for await (const chunk of stream) { line += chunk; check(line.length <= 65536, 'reply bound'); }
    check(line.endsWith('\n') && line.indexOf('\n') === line.length - 1, 'reply framing');
    const reply = JSON.parse(line);
    check(typeof reply.ok === 'boolean' && Number.isSafeInteger(reply.timestamp) && Math.abs(Date.now() / 1000 - reply.timestamp) <= 60
      && reply.request_nonce === nonce && typeof reply.nonce === 'string', 'reply freshness');
    // These specific Go body values contain only ASCII account IDs, keys,
    // digests and compact JWTs, for which JSON.stringify preserves the bytes.
    const message = [reply.ok, reply.diagnostic ?? '', reply.message ?? '', reply.state ?? '',
      reply.body ? JSON.stringify(reply.body) : '', reply.timestamp, reply.nonce, nonce].join('\n');
    check(verify(null, Buffer.from(message), machine, Buffer.from(reply.signature, 'base64')), 'Machine response signature');
    return reply;
  } finally { stream.destroy(); }
}

export function startWhoami({ stage, socket, epoch, expectedThumb, issuerDir }) {
  hosted();
  privateIssuerDir(issuerDir);
  const issuer = createPrivateKey({ key: readFileSync(join(issuerDir, 'issuer.key')), type: 'pkcs8', format: 'der' });
  function request(option, fields = {}) {
    const proc = spawnSync('/usr/bin/sudo', ['-n', '-H', '-u', role, '--', '/usr/bin/env', '-i',
      'GITHUB_ACTIONS=true', 'RUNNER_ENVIRONMENT=github-hosted', 'MM_KEYD_CUSTODY_TEST=1',
      join(stage, 'node'), join(stage, 'hosted-whoami.mjs'), 'role-request', socket, epoch, option], {
      cwd: '/', input: JSON.stringify(fields), encoding: 'utf8', timeout: 10_000, maxBuffer: 64 * 1024,
    });
    check(proc.status === 0 && !proc.stderr, 'role ' + option);
    return JSON.parse(proc.stdout);
  }
  return verifyBoundSession(request, issuer, epoch, expectedThumb);
}

// Protocol-only checks can also run against the separate disposable software
// provider. The hosted entry above always uses the operating system role.
export function verifyBoundSession(request, issuer, epoch, expectedThumb) {
  function success(option, state, fields) {
    const r = request(option, fields);
    check(r.ok === true && r.state === state && r.body.hq_epoch === epoch, 'accepted ' + option);
    return r.body;
  }
  const enrollment = success('enrollment-proof', 'proved');
  check(enrollment.key_storage === 'hardware' && jwkID(enrollment.jwk) === expectedThumb && enrollment.thumbprint === expectedThumb, 'hardware identity');
  const enrollClaims = verifyJWS(enrollment.proof, enrollment.jwk, 'ab-enroll+jwt');
  check(enrollClaims.aud === origin + '/oauth/device_authorization', 'enrollment audience');
  const device = 'native-fixture-' + randomBytes(12).toString('hex');
  const grant = receipt(issuer, { token_type: 'N_A', device_id: device, jkt: expectedThumb, harnesses: [], read_only: true },
    'enroll-v1:' + digest(enrollment.proof, 'hex'));
  check(success('bind-enrollment', 'bound', grant).device_id === device, 'enrolled device');
  const access = success('access-assertion', 'asserted');
  const assertion = verifyJWS(access.assertion, enrollment.jwk, 'JWT');
  check(exactFields(assertion, ['iss', 'sub', 'aud', 'cnf', 'iat', 'exp', 'jti'])
    && assertion.iss === device && assertion.sub === device && assertion.aud === origin + '/oauth/token'
    && assertion.exp === assertion.iat + 120 && exactFields(assertion.cnf, ['jwk'])
    && exactFields(assertion.cnf.jwk, ['kty', 'crv', 'x', 'y']), 'access assertion');
  const session = jwkID(assertion.cnf.jwk), token = randomBytes(32).toString('base64url');
  check(session !== expectedThumb, 'separate session key');
  const accepted = success('bind-access', 'access-bound', receipt(issuer, {
    device_id: device, token_type: 'DPoP', access_token: token, expires_in: 900, harnesses: [],
  }, assertion.jti));
  check(accepted.session === session && accepted.expires_at > Date.now() / 1000, 'issued session');
  const wrongSession = request('whoami', { session: expectedThumb });
  check(wrongSession.ok === false && wrongSession.diagnostic === 'MM_DAEMON_UNIMPLEMENTED'
    && !Object.hasOwn(wrongSession, 'body'), 'device key refused as session selector');
  const seen = new Set();
  return {
    checkOnline() {
      const current = success('whoami', 'whoami-proved', { session });
      check(exactFields(current, ['hq_epoch', 'session', 'proof']) && current.session === session, 'returned session');
      const p = verifyJWS(current.proof, assertion.cnf.jwk, 'dpop+jwt');
      check(exactFields(p, ['htu', 'htm', 'ath', 'iat', 'jti']) && p.htm === 'GET' && p.htu === origin + '/api/daemon/whoami'
        && p.ath === digest(token, 'base64url') && !seen.has(p.jti), 'bound fresh self-lookup');
      seen.add(p.jti);
    },
    checkOffline() {
      check(request('whoami', { session }).offline === true, 'offline socket refused');
    },
    checkRevoked() {
      const r = request('whoami', { session });
      check(r.ok === false && r.diagnostic === 'MM_DAEMON_PEER_REFUSED' && !Object.hasOwn(r, 'body'), 'signed revoked refusal');
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [op, ...args] = process.argv.slice(2);
    if (op === 'create-issuer' && args.length === 1) createTestIssuer(args[0]);
    else if (op === 'role-request' && args.length === 3) {
      const reply = await roleRequest(...args, JSON.parse(readFileSync(0, 'utf8')));
      process.stdout.write(JSON.stringify(reply)); // captured exclusively by the parent test process
    } else check(false, 'fixture arguments');
  } catch {
    process.stderr.write('FAIL native self-lookup fixture\n');
    process.exitCode = 1;
  }
}
