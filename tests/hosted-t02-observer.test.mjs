import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { test } from 'node:test';
import { superviseT02 } from './fixtures/hosted-t02-observer.mjs';

const expected = { hqCommit: 'a'.repeat(40), roleUid: 309, machineUid: 501 };
const report = {
  scope: 'T02 paired positive signing observation', outcome: 'observed', host_qualification: 'not_assessed',
  platform: 'darwin', arch: 'arm64',
  hq_commit: expected.hqCommit, hq_uid: expected.roleUid, machine_socket_uid: expected.machineUid, signed_status_state: 'idle',
  verified_es256: true, offline_refusal: 'credential_unavailable', same_pairing_and_generation: true, fresh_proof: true,
  scratch_signer_paths_absent: ['signer/device-key.pem', 'signer/pin.json'],
};

function stub(source) {
  return spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: ['pipe', 'pipe', 'pipe'] });
}

test('supervisor waits for two ordered observer checkpoints and checks the finished report', async () => {
  const child = stub(`
    import { createInterface } from 'node:readline';
    const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
    console.error('T02:before');
    if ((await lines.next()).value !== 'stopped') process.exit(1);
    console.error('T02:offline');
    if ((await lines.next()).value !== 'restarted') process.exit(1);
    console.log(${JSON.stringify(JSON.stringify(report))});
  `);
  const observer = superviseT02(child, expected, 5_000);
  try {
    await observer.before();
    child.stdin.write('stopped\n');
    await observer.offline();
    child.stdin.end('restarted\n');
    assert.deepEqual(await observer.result(), report);
  } finally { await observer.abort(); }
});

test('supervisor refuses a skipped outage and a mismatched host claim', async () => {
  const skippedChild = stub(`console.error('T02:offline');`);
  const skipped = superviseT02(skippedChild, expected, 5_000);
  try { await assert.rejects(skipped.before(), /did not reach the before checkpoint/); }
  finally { await skipped.abort(); }

  const changed = { ...report, host_qualification: 'physical' };
  const child = stub(`console.error('T02:before'); console.error('T02:offline'); console.log(${JSON.stringify(JSON.stringify(changed))});`);
  const observer = superviseT02(child, expected, 5_000);
  try {
    await observer.before();
    await observer.offline();
    await assert.rejects(observer.result(), /unexpected T02 observer report/);
  } finally { await observer.abort(); }
});
