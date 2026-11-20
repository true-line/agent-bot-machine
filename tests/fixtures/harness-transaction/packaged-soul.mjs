// Runs only under the freshly provisioned HQ role in the hosted transaction.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const load = (root, file) => import(pathToFileURL(join(root, file)));
const json = path => JSON.parse(readFileSync(path, 'utf8'));
const results = (core, kind) => core.receipts.filter(row => row.kind === kind);
const one = (rows, label) => { assert.equal(rows.length, 1, label); return rows[0]; };

// Each mapping is the lead of a separate one-member Soul. Thus the fixed
// adapter's ordinary prompt runs on both accounts without teaching it to route,
// perform a task transition or evaluate arbitrary prompt text.
export function prepareSoul(dir, id, command, env = {}) {
  const member = { member_id: id, role: 'lead', adapter_id: id, adapter_version: '0.1.0' };
  const soulId = 'agent_' + randomUUID();
  const info = JSON.stringify({ soul_id: soulId, members: [member] });
  const digest = 'sha256:' + createHash('sha256').update(info).digest('hex');
  const contents = join(dir, 'Contents');
  mkdirSync(join(contents, 'host'), { recursive: true, mode: 0o700 });
  for (const [file, bytes] of [['SoulInfo.json', info], ['SoulLock.json', JSON.stringify({ definition_digest: digest })],
    ['host/adapters.json', JSON.stringify({ [id]: { command: [command], env } })]]) {
    writeFileSync(join(contents, file), bytes, { flag: 'wx', mode: 0o600 });
  }
  return { dir, member: id, soulId, digest };
}

export async function offerAndCheck(owner, hq, soul) {
  const operationId = 'offer_' + randomUUID();
  const payload = { operation_id: operationId, objective: 'Check in on the assigned account.', done_criteria: 'ACP prompt returns.',
    accountable_soul: soul.soulId, write_scope: ['workspace:fixture'] };
  const reply = await owner.request('tasks.offer', payload);
  assert.equal(reply.ok, true, 'owner task offer refused');
  const receipt = reply.result;
  assert.equal(receipt.status, 'offered');
  assert.equal(receipt.profile, 'managed-cooperative');
  assert.equal(receipt.outcome, 'committed');
  assert.equal(receipt.by, 'owner');
  assert.equal(receipt.operation_id, operationId);
  assert.deepEqual((await owner.request('tasks.offer', payload)).result, receipt, 'task retry changed its receipt');
  const read = await owner.request('tasks.get', { task_id: receipt.task_id });
  assert.equal(read.result.task.accountable_soul, soul.soulId);
  assert.equal(read.result.task.status, 'offered');
  const stored = one(results(hq.core, 'task.offer').filter(r => r.operation_id === operationId), 'one committed offer');
  assert.equal(stored.receipt_id, receipt.receipt_id);
  assert.equal(stored.profile, receipt.profile);
  return receipt.task_id;
}

function verifyLaunch(core, role, soul, runtime, uid) {
  const rt = core.tables.get('hq-admission\0runtimes').get(runtime);
  assert.equal(rt.soul_id, soul.soulId);
  assert.equal(rt.member_id, soul.member);
  assert.equal(rt.harness_account, role);
  assert.equal(rt.harness_uid, uid);
  const start = one(results(core, 'hq.launch').filter(r => r.runtime_id === runtime), 'one supervised launch');
  assert.equal(start.account, role);
  assert.equal(start.soul_id, soul.soulId);
  const binds = results(core, 'hq.bind').filter(r => r.runtime_id === runtime);
  assert.ok(binds.length >= 1);
  for (const row of binds) {
    assert.equal(row.proof, 'hmac-sha256');
    assert.equal(row.caller_account, role);
    assert.equal(row.profile, 'managed-cooperative');
  }
  return start.launch_id;
}

async function run() {
  assert.equal(process.platform, 'darwin');
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(userInfo().username, '_agent-bot-hq');
  const [code, souls, state, policyFile] = process.argv.slice(2);
  const fixed = json(policyFile);
  const provenance = json(join(code, 'governance/interim-release.json'));
  assert.equal(provenance.hq_commit, '1d3761e77e6b77a451347839a04dd4cea7a47904');
  const { createHQ } = await load(code, 'hq/hq.mjs');
  const { connectSocket } = await load(code, 'hq/socket.mjs');
  const { readPins, productionPluginsDir } = await load(code, 'hq/plugins.mjs');
  const { schemas } = await load(code, 'tests/hq-harness.mjs');
  const { startSoul } = await load(souls, 'lib/entry-point.mjs');
  const home = join(state, 'hq');
  mkdirSync(home, { mode: 0o700 });
  const definitions = Object.keys(fixed.mappings).map((id, i) => prepareSoul(join(state, 's' + i), id, fixed.executable));
  const accounts = Object.values(fixed.mappings);
  const uids = accounts.map(account => Number(execFileSync('/usr/bin/id', ['-u', account], { encoding: 'utf8' }).trim()));
  assert.equal(new Set([process.getuid(), ...uids]).size, 3);
  const pins = readPins(join(code, 'governance/plugins.json'));
  const pluginsDir = productionPluginsDir({}, join(code, 'hq/interim-core.mjs'), pins);
  const hq = createHQ({ home, schemas, config: {
    harnesses: { dir: '/Library/Application Support/ai.true-line.agent-bot-hq/ipc', accounts: fixed.mappings },
    acceptedDefinitions: Object.fromEntries(definitions.map(s => [s.soulId, [s.digest]])),
  }, pins, pluginsDir,
  signer: { deviceStatus: async () => 'enrolled' }, launch: {
    qualifiedDarwinAdapter: a => Object.hasOwn(fixed.mappings, a.adapter_id) && fixed.mappings[a.adapter_id] === a.account &&
      uids[accounts.indexOf(a.account)] === a.uid && a.executable === fixed.executable && a.sha256 === fixed.sha256 &&
      Array.isArray(a.args) && a.args.length === 0,
  } });
  const sessions = [];
  let owner;
  try {
    const status = await hq.start();
    assert.equal(status.mode, 'running');
    assert.equal(status.profile, 'managed-cooperative');
    const loaded = one(status.hq.pluginLoad.filter(p => p.name === 'agent-comms'), 'one pinned broker');
    assert.equal(loaded.state, 'loaded');
    assert.equal(loaded.digest, provenance.broker.sha256);
    assert.ok(!loaded.dev && !status.hq.devPlugins);
    for (const account of accounts) assert.equal(status.hq.launch.accounts.find(a => a.account === account)?.available, true);
    owner = await connectSocket(hq.paths.control);
    const launched = new Set(), tasks = new Set(), runtimes = [];
    for (const [i, definition] of definitions.entries()) {
      const soul = await startSoul({ root: definition.dir, hqHome: home, renewEveryMs: 0,
        env: { AGENT_BOT_SOUL_CONTRACTS: join(code, 'vendor/soul-contracts') } });
      sessions.push(soul);
      tasks.add(await offerAndCheck(owner, hq, definition));
      const turn = await soul.prompt('Check in on the assigned account.');
      assert.equal(turn.stop_reason, 'end_turn');
      assert.equal(turn.member_id, definition.member);
      assert.ok(soul.events().some(e => e.event === 'member-started' && e.launch === 'hq'));
      assert.ok(!soul.events().some(e => e.event.includes('fallback')));
      const runtime = soul.status().members[0].runtime_id;
      launched.add(verifyLaunch(hq.core, accounts[i], definition, runtime, uids[i]));
      runtimes.push(runtime);
    }
    assert.equal(launched.size, 2);
    assert.equal(tasks.size, 2);
    assert.equal(new Set(runtimes).size, 2);
    await sessions.shift().stop();
    const previous = results(hq.core, 'hq.bind').filter(r => r.runtime_id === runtimes[1]).length;
    assert.equal((await sessions[0].prompt('Check in again.')).stop_reason, 'end_turn');
    assert.equal(results(hq.core, 'hq.bind').filter(r => r.runtime_id === runtimes[1]).length, previous + 1);
    await sessions.shift().stop();
    for (const id of launched) {
      assert.equal(one(results(hq.core, 'hq.launch.exited').filter(r => r.launch_id === id), 'one supervisor exit').contained, true);
    }
    console.log('Packaged HQ constructor and pinned broker verified two account-bound Souls, HMAC binds, task offers and contained stops.');
  } finally {
    try { for (const soul of sessions.reverse()) await soul.stop(); }
    finally { try { if (owner) await owner.close(); } finally { await hq.stop(); } }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await run();
}
