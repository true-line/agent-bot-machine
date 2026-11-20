// Hosted pre-release native acceptance. Only disposable keys cross this test
// setup; role requests themselves pass through the signed UNIX socket.
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as pause } from 'node:timers/promises';

function requireCheck(ok) {
  if (!ok) throw new Error('dedicated role native custody fixture failed');
}

export async function exerciseNativeChannel(stage, machine, hq, epoch, expectedThumb) {
  const socket = join(stage, 'device.sock');
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
  let server, outstanding;
  try {
    check('outage');
    server=await start();
    requireCheck(check('identity')===expectedThumb);
    const proofIdBefore = check('prove');
    requireCheck(/^[0-9a-f]{64}$/.test(proofIdBefore));
    await stop(server);server=undefined;
    check('outage');
    server=await start();
    requireCheck(check('identity')===expectedThumb);
    const proofIdAfter = check('prove');
    requireCheck(/^[0-9a-f]{64}$/.test(proofIdAfter) && proofIdAfter !== proofIdBefore);
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
  } finally {
    if(outstanding)outstanding.kill();
    if(server && server.exitCode===null)await stop(server);
    adminSeed.fill(0);
  }
  console.log('PASS dedicated HQ native custody, Machine outage, restart, and queued and new request refusal after revoke');
}
