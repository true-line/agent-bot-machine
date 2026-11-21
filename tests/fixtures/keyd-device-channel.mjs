// Hosted pre-release native acceptance. Only disposable keys cross this test
// setup; role requests themselves pass through the signed UNIX socket.
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as pause } from 'node:timers/promises';

function requireCheck(ok) {
  if (!ok) throw new Error('dedicated role native custody fixture failed');
}

// Run the same packaged CLI controller as the signed release lane. It receives
// only the independently observed device thumbprint and named checkpoints.
function startPackagedController(stage, role, thumb) {
  const child = spawn('/usr/bin/sudo', ['-n', '-H', '-u', role, '--', '/usr/bin/env', '-i',
    'PATH=/usr/bin:/bin', 'GITHUB_ACTIONS=true', 'RUNNER_ENVIRONMENT=github-hosted',
    join(stage, 'node'), join(stage, 'packaged-device.mjs'), thumb], { cwd: '/', stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = createInterface({input: child.stdout})[Symbol.asyncIterator]();
  const closed = new Promise(resolve => {
    child.once('error', () => resolve(1));
    child.once('close', resolve);
  });
  child.stdin.on('error', () => {}); // An early exit is reported by the closed response stream.
  async function expect(name) {
    const timer = new AbortController();
    try {
      const timeout = pause(30_000, undefined, { signal: timer.signal }).then(() => { throw new Error('packaged HQ timed out at ' + name); });
      const line = await Promise.race([lines.next(), timeout]);
      if (line.done || line.value !== name) throw new Error('packaged HQ did not complete ' + name);
    } finally { timer.abort(); }
  }
  return {
    ready: () => expect('ready'),
    async step(name) { child.stdin.write(name + '\n'); await expect(name); },
    async stop() { child.stdin.end('stop\n'); requireCheck(await closed === 0); },
    async abort() { child.stdin.end(); await closed; },
  };
}

function startWarmController(stage, role, thumb) {
  const child = spawn('/usr/bin/sudo', ['-n', '-H', '-u', role, '--', '/usr/bin/env', '-i',
    'PATH=/usr/bin:/bin', 'GITHUB_ACTIONS=true', 'RUNNER_ENVIRONMENT=github-hosted',
    join(stage, 'node'), join(stage, 'hq-warm-revoke.mjs'), stage, thumb],
  { cwd: '/', stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  const closed = new Promise(resolve => { child.once('error', () => resolve(1)); child.once('close', resolve); });
  child.stdin.on('error', () => {});
  async function expect(value) {
    const timer = new AbortController();
    try {
      const timeout = pause(30_000, undefined, { signal: timer.signal }).then(() => { throw new Error('HQ warm fixture timed out'); });
      const line = await Promise.race([lines.next(), timeout]);
      requireCheck(!line.done && line.value === value);
    } finally { timer.abort(); }
  }
  return {
    ready: () => expect('warm'),
    async revoke() { child.stdin.write('revoked\n'); await expect('revoked'); child.stdin.end(); requireCheck(await closed === 0); },
    async abort() { child.kill(); await closed; },
  };
}

async function startIndependentObserver(stage, role, roleUid) {
  const root = join(stage, 't02-observer');
  const conformanceCommit = readFileSync(join(root, 'conformance-commit'), 'ascii').trim();
  const hqCommit = JSON.parse(readFileSync(join(root, 'governance/archives.json'), 'utf8')).archives['t02-hq'].commit;
  const { superviseT02 } = await import('./hosted-t02-observer.mjs');
  const child = spawn('/usr/bin/sudo', ['-n', '-H', '-u', role, '--', '/usr/bin/env', '-i',
    'PATH=/usr/bin:/bin', join(stage, 'node'), join(root, 'suites/T02-key-boundary/paired-proof.mjs'),
    '--verified-cache', join(root, 'cache'), '--disposable', '--checkpoints'], { cwd: '/', stdio: ['ignore', 'pipe', 'pipe'] });
  return { conformanceCommit, ...superviseT02(child, { hqCommit, roleUid, machineUid: process.getuid() }) };
}

export async function exerciseNativeChannel(stage, machine, hq, epoch, expectedThumb, roleUid) {
  const socket = '/opt/homebrew/var/agent-machine/daemon.sock';
  const role = '_agent-bot-hq';
  const adminSeed = Buffer.from(machine.privateKey.export({ format: 'jwk' }).d, 'base64url');
  const pub = key => Buffer.from(key.export({ format: 'jwk' }).x, 'base64url').toString('base64');
  const roleMaterial = { 'client.key': hq.privateKey.export({ format: 'jwk' }).d,
    'client.pub': pub(hq.publicKey), 'daemon.pub': pub(machine.publicKey) };
  // Only the synthetic channel-authentication credential goes into the role.
  const setup = spawnSync('/usr/bin/sudo', ['-n', '-H', '-u', role, '--', join(stage,'node'), '--input-type=module', '-e',
    `import {mkdirSync,readFileSync,writeFileSync} from 'node:fs'; import {join} from 'node:path'; import {userInfo} from 'node:os';
    const u=userInfo(); if(u.username!=='_agent-bot-hq')process.exit(1);
    const base=join(u.homedir,'.config'); mkdirSync(base,{mode:0o700});
    const dir=join(base,'agent-machine');mkdirSync(dir,{mode:0o700});
    for(const [k,v] of Object.entries(JSON.parse(readFileSync(0)))) writeFileSync(join(dir,k),Buffer.from(v,'base64'),{mode:0o600,flag:'wx'});`],
  { cwd:'/', input:JSON.stringify(roleMaterial), stdio:['pipe','ignore','ignore'] });
  requireCheck(setup.status===0);
  const args = op => ['-n','-H','-u',role,'--','/usr/bin/env','GITHUB_ACTIONS=true',join(stage,'node'),join(stage,'role-check.mjs'),op,socket,epoch,
    ...(op === 'prove' ? [expectedThumb] : [])];
  const check = op => {
    const r=spawnSync('/usr/bin/sudo',args(op),{cwd:'/',encoding:'utf8',timeout:8000,maxBuffer:2048});
    requireCheck(r.status===0);return r.stdout.trim();
  };
  const start = async () => {
    const child=spawn(join(stage,'machine-test'),['-test.run=^TestHostedNativeDeviceMachine$','-test.timeout=90s'],{
      cwd:'/',env:{PATH:'/usr/bin:/bin',GITHUB_ACTIONS:'true',RUNNER_ENVIRONMENT:'github-hosted',MM_NATIVE_KEYD_CHANNEL:'1'},stdio:['pipe','ignore','ignore']});
    child.stdin.end(adminSeed);
    for(let i=0;i<80&&!existsSync(socket)&&child.exitCode===null;i++)await pause(50);
    if (!existsSync(socket)) {child.kill();throw Error('test listener unavailable');}
    return child;
  };
  const stop = async child => {
    const closed=once(child,'exit'); child.kill('SIGTERM'); await closed;
    requireCheck(!existsSync(socket));
  };
  let server, outstanding, packaged, observer, warm;
  try {
    if (process.env.MM_NATIVE_WHOAMI_TEST === '2') {
      server = await start();
      warm = startWarmController(stage, role, expectedThumb);
      await warm.ready();
      const revoke = spawnSync(join(stage, 'managed-machine'), ['daemon', 'revoke-hq'], {
        cwd: '/', stdio: 'ignore', timeout: 5000,
      });
      requireCheck(revoke.status === 0);
      // A verified signed refusal confirms this is revocation, not a lost
      // Machine socket, on both sides of the warmed client's request.
      check('refused');
      await warm.revoke();
      check('refused');
      warm = undefined;
      console.log('PASS enrolled HQ warmed one native Machine session; admin revoke cleared its token and blocked issuer calls');
      return;
    }
    if (process.env.MM_NATIVE_WHOAMI_TEST === '1') {
      server = await start();
      const { startWhoami } = await import('./hosted-whoami.mjs');
      const session = startWhoami({ stage, socket, epoch, expectedThumb, issuerDir: join(stage, 'issuer') });
      session.checkOnline();
      await stop(server);
      server = undefined;
      session.checkOffline();
      server = await start();
      session.checkOnline();
      const revoke = spawnSync(join(stage, 'managed-machine'), ['daemon', 'revoke-hq'], {
        cwd: '/', stdio: 'ignore', timeout: 5000,
      });
      requireCheck(revoke.status === 0);
      session.checkRevoked();
      await stop(server);
      server = undefined;
      server = await start();
      session.checkRevoked();
      console.log('PASS dedicated role verified native session self-lookup, outage, restart and signed revocation');
      return;
    }
    check('outage');
    server=await start();
    requireCheck(check('identity')===expectedThumb);
    const proofIdBefore = check('prove');
    requireCheck(/^[0-9a-f]{64}$/.test(proofIdBefore));
    packaged = startPackagedController(stage, role, expectedThumb);
    await packaged.ready();
    await packaged.step('prove');
    if (existsSync(join(stage, 't02-observer'))) {
      observer = await startIndependentObserver(stage, role, roleUid);
      await observer.before();
    }
    await stop(server);server=undefined;
    check('outage');
    await packaged.step('outage');
    await observer?.offline();
    server=await start();
    if (observer) {
      const report = await observer.result();
      console.log(JSON.stringify({ conformance_commit: observer.conformanceCommit, hardware_probe: 'available', observer: report }));
      observer = undefined;
    }
    requireCheck(check('identity')===expectedThumb);
    const proofIdAfter = check('prove');
    requireCheck(/^[0-9a-f]{64}$/.test(proofIdAfter) && proofIdAfter !== proofIdBefore);
    await packaged.step('recovered');
    outstanding=spawn('/usr/bin/sudo',args('deferred'),{cwd:'/',stdio:['pipe','pipe','ignore']});
    const finished=once(outstanding,'exit');
    const [connected]=await once(outstanding.stdout,'data',{signal:AbortSignal.timeout(5000)});
    requireCheck(connected.toString().trim()==='connected');
    const revoke=spawnSync(join(stage,'managed-machine'),['daemon','revoke-hq'],{cwd:'/',stdio:'ignore',timeout:5000});
    requireCheck(revoke.status===0);
    outstanding.stdin.end('send\n');
    requireCheck((await finished)[0]===0);
    outstanding=undefined;
    check('refused');
    await stop(server);server=undefined;
    server=await start(); check('refused');
    await packaged.step('revoked');
    await packaged.stop();
    packaged = undefined;
    console.log('PASS packaged dedicated HQ on the native Machine channel: fresh hardware proofs, outage, recovery and denial after revocation and HQ restart');
  } finally {
    try { await observer?.abort(); }
    finally {
      await warm?.abort();
      await packaged?.abort();
      if(outstanding)outstanding.kill();
      if(server && server.exitCode===null)await stop(server);
      adminSeed.fill(0);
    }
  }
  console.log('PASS dedicated HQ native custody, Machine outage, restart, and queued and new request refusal after revoke');
}
