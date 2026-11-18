import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { download, openReleasePR, validateDraft } from '../scripts/prepare-release.mjs';

const sha = '1'.repeat(40);
const releaseSha = '2'.repeat(40);
const tree = '3'.repeat(40);
const version = '0.12.1';
const repository = 'true-line/agent-bot-machine';
const bot = 'trueline-chores-dumb[bot]';
const rest = '/repos/' + repository;
const branch = 'release/v' + version;
const options = { version, sha, tree, additions: [{ path: 'VERSION', contents: 'MC4xMi4xCg==' }] };

function fixture() {
  const state = { currentMain: sha, branch: null, tag: null, prs: [], writes: [], commitTree: tree, verified: true, author: bot, requestVersion: version };
  const call = async (path, args = {}) => {
    const route = path.replace(rest, '');
    if (args.method === 'POST') state.writes.push(path);
    switch (route) {
      case '/git/ref/heads/main': return { object: { sha: state.currentMain } };
      case '/contents/.github/machine-release-version?ref=' + state.currentMain:
        return { content: Buffer.from(state.requestVersion).toString('base64') };
      case '/git/ref/tags/v' + version: return state.tag;
      case '/git/ref/heads/' + branch: return state.branch && { object: { sha: state.branch } };
      case '/git/refs':
        assert.deepEqual(args.data, { ref: 'refs/heads/' + branch, sha });
        state.branch = sha;
        return {};
      case '/graphql':
        assert.equal(args.data.variables.input.expectedHeadOid, sha);
        assert.deepEqual(args.data.variables.input.fileChanges.additions, options.additions);
        assert.deepEqual(args.data.variables.input.branch, { repositoryNameWithOwner: repository, branchName: branch });
        state.branch = releaseSha;
        return { data: { createCommitOnBranch: { commit: { oid: releaseSha } } } };
      case '/commits/' + releaseSha:
        return { author: { login: state.author }, parents: [{ sha }], commit: { tree: { sha: state.commitTree }, message: 'Release v' + version, verification: { verified: state.verified } } };
      case '/pulls?state=all&base=main&head=' + encodeURIComponent('true-line:' + branch): return state.prs;
      case '/pulls':
        assert.equal(state.branch, releaseSha);
        assert.equal(args.data.head, branch);
        assert.equal(args.data.base, 'main');
        state.prs = [{ state: 'open', user: { login: bot }, head: { sha: releaseSha, repo: { full_name: repository } }, html_url: 'https://example.invalid/pull/1' }];
        return state.prs[0];
      default: throw new Error('Unexpected API route: ' + route);
    }
  };
  return { state, call };
}

test('fresh preparation writes only the branch, signed commit, and review PR; reruns leave them alone', async () => {
  const { state, call } = fixture();
  await openReleasePR(options, call);
  assert.deepEqual(state.writes, [rest + '/git/refs', '/graphql', rest + '/pulls']);
  state.writes.length = 0;
  await openReleasePR(options, call);
  assert.deepEqual(state.writes, []);
});

test('retries after the ref or commit already exists', async () => {
  for (const [head, writes] of [[sha, ['/graphql', rest + '/pulls']], [releaseSha, [rest + '/pulls']]]) {
    const { state, call } = fixture();
    state.branch = head;
    await openReleasePR(options, call);
    assert.deepEqual(state.writes, writes);
  }
});

test('superseded request and existing tag perform no writes', async () => {
  for (const overrides of [{ currentMain: releaseSha, requestVersion: '0.12.2' }, { tag: { object: { sha: releaseSha } } }]) {
    const { state, call } = fixture();
    Object.assign(state, overrides);
    await openReleasePR(options, call);
    assert.deepEqual(state.writes, []);
  }
});

test('main changing under the same request fails with a concrete recovery', async () => {
  const { state, call } = fixture();
  state.currentMain = releaseSha;
  await assert.rejects(() => openReleasePR(options, call), /new reviewed version request/);
  assert.deepEqual(state.writes, []);
});

test('foreign or unsigned commit and a closed PR are left intact', async () => {
  for (const overrides of [{ commitTree: 'other' }, { verified: false }, { author: 'other[bot]' }, { prs: [{ state: 'closed' }] }]) {
    const { state, call } = fixture();
    Object.assign(state, { branch: releaseSha }, overrides);
    await assert.rejects(() => openReleasePR(options, call));
    assert.deepEqual(state.writes, []);
  }
});

test('draft must name exact Sign SHA and version, with exactly five archives and checksum manifest', () => {
  const names = ['darwin_arm64.tar.gz', 'linux_arm64.tar.gz', 'linux_amd64.tar.gz', 'windows_arm64.zip', 'windows_amd64.zip'].map(s => 'managed-machine_' + version + '_' + s);
  const draft = {
    draft: true, tag_name: 'v' + version, target_commitish: sha,
    assets: ['SHA256SUMS', ...names].map((name, i) => ({ id: i+1, name, digest: 'sha256:' + '4'.repeat(64), state: 'uploaded' })),
  };
  validateDraft(draft, version, sha);
  for (const change of [{ target_commitish: 'main' }, { draft: false }, { tag_name: 'v0.12.0' },
    { assets: draft.assets.slice(1) }, { assets: [...draft.assets, draft.assets[0]] },
    { assets: draft.assets.map(a => ({...a, digest: null})) }]) {
    assert.throws(() => validateDraft({ ...draft, ...change }, version, sha));
  }
});

test('download checks the bytes of each asset and refuses a corrupt response', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mm-prepare-'));
  const payload = Buffer.from('release artifact');
  const digest = 'sha256:' + createHash('sha256').update(payload).digest('hex');
  const assets = ['SHA256SUMS', ...['darwin_arm64.tar.gz', 'linux_amd64.tar.gz', 'linux_arm64.tar.gz',
    'windows_amd64.zip', 'windows_arm64.zip'].map(s => 'managed-machine_' + version + '_' + s)]
    .map((name, i) => ({ name, id: i + 7, state: 'uploaded', digest }));
  const draft = { draft: true, tag_name: 'v' + version, target_commitish: sha, assets };
  let corrupt = false;
  const call = async (path, args) => {
    if (path === rest + '/releases?per_page=100&page=1') return [draft];
    assert.equal(args.binary, true);
    assert.ok(assets.some(a => path === rest + '/releases/assets/' + a.id));
    return corrupt ? Buffer.from('corrupt payload') : payload;
  };
  try {
    await download(version, sha, join(root, 'valid'), call);
    assert.deepEqual((await readdir(join(root, 'valid'))).sort(), assets.map(a => a.name).sort());
    corrupt = true;
    await assert.rejects(() => download(version, sha, join(root, 'corrupt'), call));
    assert.deepEqual(await readdir(join(root, 'corrupt')), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
