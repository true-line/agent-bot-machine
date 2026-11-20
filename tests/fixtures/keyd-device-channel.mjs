// Hosted pre-release native acceptance. Only disposable keys cross this test
// setup; role requests themselves pass through the signed UNIX socket.
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
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

export async function exerciseNativeChannel(stage, machine, hq, epoch, expectedThumb) {
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
  let server, outstanding, packaged;
  try {
    check('outage');
    server=await start();
    requireCheck(check('identity')===expectedThumb);
    const proofIdBefore = check('prove');
    requireCheck(/^[0-9a-f]{64}$/.test(proofIdBefore));
    packaged = startPackagedController(stage, role, expectedThumb);
    await packaged.ready();
    await packaged.step('prove');
    await stop(server);server=undefined;
    check('outage');
    await packaged.step('outage');
    server=await start();
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
    await packaged?.abort();
    if(outstanding)outstanding.kill();
    if(server && server.exitCode===null)await stop(server);
    adminSeed.fill(0);
  }
  console.log('PASS dedicated HQ native custody, Machine outage, restart, and queued and new request refusal after revoke');
}
