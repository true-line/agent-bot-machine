import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { download, downloadOwner, openReleasePR, validateDraft } from '../scripts/prepare-release.mjs';

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


test('only trusted workflow code runs in both jobs, before draft access or App credential creation', async () => {
  const yml = await readFile(new URL('../.github/workflows/prepare-release.yml', import.meta.url), 'utf8');
  const jobs = yml.split('  open-pr:');
  assert.equal(jobs.length, 2);
  assert.match(jobs[0], /github.ref == 'refs\/heads\/main' && github.ref_protected/);
  for (const [i, job] of jobs.entries()) {
    assert.ok(job.includes('ref: ${{ github.sha }}'));
    assert.ok(!job.includes('ref: ${{ github.event.workflow_run.head_sha }}'));
    const check = job.indexOf('scripts/prepare-release.mjs eligible-version');
    assert.ok(check > job.indexOf('ref: ${{ github.sha }}'));
    assert.ok(check < job.indexOf(i === 0 ? 'Read the signed draft' : 'Mint the release PR App token'));
  }
});

test('Sign eligibility uses the checked-out workflow SHA, protected main tip, and main history', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mm-sign-eligibility-'));
  const script = fileURLToPath(new URL('../scripts/prepare-release.mjs', import.meta.url));
  const source = join(root, 'source');
  const checkout = join(root, 'checkout');
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_ALLOW_PROTOCOL: 'file',
    GIT_AUTHOR_NAME: 'test', GIT_AUTHOR_EMAIL: 'test@example.invalid',
    GIT_COMMITTER_NAME: 'test', GIT_COMMITTER_EMAIL: 'test@example.invalid' };
  function git(cwd, ...args) {
    const result = spawnSync('git', args, { cwd, env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  }
  function check(trustedSha, signSha) {
    return spawnSync(process.execPath, [script, 'eligible-version', signSha], {
      cwd: checkout, env: { ...env, GITHUB_REPOSITORY: repository, GITHUB_SHA: trustedSha }, encoding: 'utf8',
    });
  }
  try {
    git(root, 'init', '-q', '-b', 'main', source);
    await mkdir(join(source, '.github'));
    await writeFile(join(source, '.github/machine-release-version'), version + '\n');
    git(source, 'add', '.github');
    git(source, 'commit', '-qm', 'request release');
    const sign = git(source, 'rev-parse', 'HEAD');
    git(root, 'clone', '-q', source, checkout);
    assert.equal(check(sign, sign).stdout.trim(), version);
    git(source, 'switch', '-qc', 'elsewhere');
    git(source, 'commit', '--allow-empty', '-qm', 'outside main');
    const outside = git(source, 'rev-parse', 'HEAD');
    git(checkout, 'fetch', '-q', 'origin', 'refs/heads/elsewhere');
    assert.notEqual(check(sign, outside).status, 0);
    git(source, 'switch', '-q', 'main');
    git(source, 'commit', '--allow-empty', '-qm', 'advance main');
    const next = git(source, 'rev-parse', 'HEAD');
    assert.notEqual(check(sign, sign).status, 0);
    assert.notEqual(check(sign, next).status, 0);
    assert.notEqual(check(next, sign).status, 0);
    await writeFile(join(source, '.github/machine-release-version'), '0.12.2\n');
    git(source, 'commit', '-qam', 'replace request');
    const superseded = check(sign, sign);
    assert.equal(superseded.status, 0, superseded.stderr);
    assert.equal(superseded.stdout.trim(), '');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('owner download binds the two verified assets to the reviewed version and signing commit', async t => {
  const root = await mkdtemp(join(tmpdir(), 'owner-draft-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const zip = 'AgentBotOwnerPresence_' + version + '_darwin_arm64.zip';
  const bytes = Buffer.from('fixture archive');
  const hash = body => createHash('sha256').update(body).digest('hex');
  const checksum = Buffer.from(hash(bytes) + '  ' + zip + '\n');
  async function run(name, overrides = {}, sidecar = checksum, response = bytes) {
    const assets = [zip, zip + '.sha256'].map((name, id) => ({
      id: id + 1, name, state: 'uploaded', digest: 'sha256:' + hash([bytes, sidecar][id]),
    }));
    const draft = { draft: true, tag_name: 'owner-presence-v' + version, target_commitish: sha, assets, ...overrides };
    return downloadOwner(version, sha, join(root, name), async (path, options) => {
      if (path === rest + '/releases?per_page=100&page=1') return [draft];
      assert.equal(options.binary, true);
      if (path === rest + '/releases/assets/1') return response;
      assert.equal(path, rest + '/releases/assets/2');
      return sidecar;
    });
  }
  await run('good');
  assert.deepEqual(await readFile(join(root, 'good', zip)), bytes);
  await assert.rejects(run('source', { target_commitish: releaseSha }));
  await assert.rejects(run('tag', { tag_name: 'v' + version }));
  await assert.rejects(run('public', { draft: false }));
  await assert.rejects(run('missing', { assets: [] }));
  await assert.rejects(run('sidecar', {}, Buffer.from('other checksum')));
  await assert.rejects(run('corrupt', {}, checksum, Buffer.from('corrupt archive')));
});
