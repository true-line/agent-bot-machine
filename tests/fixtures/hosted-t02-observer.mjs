// The independent observer owns verification. This controller coordinates
// its checkpoints with the existing disposable Machine restart.
import { createInterface } from 'node:readline';
import { setTimeout as pause } from 'node:timers/promises';

export function superviseT02(child, expected, timeoutMs = 30_000) {
  const lines = createInterface({ input: child.stderr })[Symbol.asyncIterator]();
  const closed = new Promise((resolve) => {
    child.once('error', () => resolve(1));
    child.once('close', resolve);
  });
  let stdout = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (data) => {
    stdout += data;
    if (stdout.length > 16_384) child.kill();
  });

  async function within(pending, description) {
    const timer = new AbortController();
    const expired = pause(timeoutMs, undefined, { signal: timer.signal }).then(() => { throw new Error(description); });
    try { return await Promise.race([pending, expired]); }
    finally { timer.abort(); }
  }

  async function checkpoint(name) {
    const next = await within(lines.next(), `T02 observer timed out before the ${name} checkpoint`);
    if (next.done || next.value !== `T02:${name}`) throw new Error(`T02 observer did not reach the ${name} checkpoint`);
  }

  return {
    before: () => checkpoint('before'),
    offline: () => checkpoint('offline'),
    async result() {
      if (await within(closed, 'T02 observer did not finish after restart') !== 0 || stdout.length > 16_384) {
        throw new Error('T02 observer failed after restart');
      }
      const report = JSON.parse(stdout);
      if (report.scope !== 'T02 paired positive signing observation' || report.outcome !== 'observed'
        || report.host_qualification !== 'not_assessed' || report.hq_commit !== expected.hqCommit
        || report.platform !== 'darwin' || report.arch !== 'arm64'
        || report.hq_uid !== expected.roleUid || report.machine_socket_uid !== expected.machineUid
        || report.signed_status_state !== 'idle' || report.verified_es256 !== true
        || report.offline_refusal !== 'credential_unavailable' || report.same_pairing_and_generation !== true
        || report.fresh_proof !== true
        || JSON.stringify(report.scratch_signer_paths_absent) !== '["signer/device-key.pem","signer/pin.json"]') {
        throw new Error('unexpected T02 observer report');
      }
      return report;
    },
    async abort() {
      if (child.exitCode === null && child.signalCode === null) child.kill();
      await within(closed, 'T02 observer did not stop');
    },
  };
}
