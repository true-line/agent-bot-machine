// Invoked only by prepare-release.yml on successful, same-repository Sign pushes.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const repo = 'true-line/agent-bot-machine';
const bot = 'trueline-chores-dumb[bot]';
const files = ['Formula/managed-machine.rb', 'VERSION'];
const api = 'https://api.github.com';
const rest = '/repos/' + repo;
const platformArchives = ['darwin_arm64.tar.gz', 'linux_amd64.tar.gz', 'linux_arm64.tar.gz', 'windows_amd64.zip', 'windows_arm64.zip'];
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
const requireState = (state, message) => { if (!state) throw new Error(message); };

async function request(path, { method = 'GET', data, optional = false, binary = false } = {}) {
  const response = await fetch(api + path, {
    method,
    headers: {
      Authorization: 'Bearer ' + process.env.API_TOKEN,
      Accept: binary ? 'application/octet-stream' : 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(data ? { 'Content-Type': 'application/json' } : {}),
    },
    body: data ? JSON.stringify(data) : undefined,
    // Fetch drops Authorization when the asset route redirects across origins.
    signal: AbortSignal.timeout(120_000),
  });
  if (optional && response.status === 404) return null;
  requireState(response.ok, method + ' ' + path + ' returned ' + response.status);
  return binary ? Buffer.from(await response.arrayBuffer()) : response.json();
}

export function validateDraft(draft, version, sha) {
  const expected = ['SHA256SUMS', ...platformArchives.map(s => 'managed-machine_' + version + '_' + s)];
  validateSignedAssets(draft, 'v' + version, sha, expected);
}

function validateSignedAssets(draft, tag, sha, names) {
  requireState(draft?.draft === true && draft.tag_name === tag && draft.target_commitish === sha,
    'The release must be a draft for this exact Sign commit and version');
  const expected = [...names].sort();
  assert.deepEqual(draft.assets.map(a => a.name).sort(), expected, 'Unexpected draft asset set');
  for (const asset of draft.assets) {
    requireState(Number.isSafeInteger(asset.id) && asset.id > 0 && asset.state === 'uploaded' &&
      /^sha256:[0-9a-f]{64}$/.test(asset.digest), 'Missing uploaded asset or digest for ' + asset.name);
  }
}

async function findDraft(tag, call) {
  // Draft releases can have no tag ref yet. The published-by-tag endpoint
  // cannot reliably see them; use the authenticated releases collection.
  let draft;
  for (let page = 1; !draft; page++) {
    const batch = await call(rest + '/releases?per_page=100&page=' + page);
    draft = batch.find(r => r.tag_name === tag);
    if (!draft && batch.length < 100) break;
  }
  return draft;
}

async function downloadAssets(draft, dir, call) {
  await mkdir(dir);
  for (const asset of draft.assets) {
    const bytes = await call(rest + '/releases/assets/' + asset.id, { binary: true });
    assert.equal('sha256:' + createHash('sha256').update(bytes).digest('hex'), asset.digest, asset.name);
    await writeFile(join(dir, asset.name), bytes, { flag: 'wx' });
  }
}

export async function download(version, sha, dir, call = request) {
  const draft = await findDraft('v' + version, call);
  validateDraft(draft, version, sha);
  await downloadAssets(draft, dir, call);
}

export async function downloadOwner(version, sha, dir, call = request) {
  const tag = 'owner-presence-v' + version;
  const zip = 'AgentBotOwnerPresence_' + version + '_darwin_arm64.zip';
  const draft = await findDraft(tag, call);
  validateSignedAssets(draft, tag, sha, [zip, zip + '.sha256']);
  await downloadAssets(draft, dir, call);
  const digest = draft.assets.find(asset => asset.name === zip).digest.slice('sha256:'.length);
  assert.equal(await readFile(join(dir, zip + '.sha256'), 'utf8'), digest + '  ' + zip + '\n',
    'Owner app checksum must identify the verified zip bytes and filename');
}

const mutation = `mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid } }
}`;

export async function openReleasePR({version, sha, tree, additions}, call = request) {
  const tag = 'v' + version;
  const branch = 'release/' + tag;
  const title = 'Release ' + tag;
  const ref = name => call(rest + '/git/ref/' + name, { optional: true });
  const head = await ref('heads/main');
  if (await ref('tags/' + tag)) {
    console.log('The release tag already exists; no release branch changes.');
    return;
  }
  if (head?.object.sha !== sha) {
    requireState(head && /^[0-9a-f]{40}$/.test(head.object.sha), 'Could not resolve main');
    const current = await call(rest + '/contents/.github/machine-release-version?ref=' + head.object.sha);
    const currentVersion = Buffer.from(current.content, 'base64').toString('utf8').trim();
    requireState(currentVersion !== version, 'Main changed after Sign for ' + tag + '. Merge a new reviewed version request to rebuild and sign current main.');
    console.log('A new release request superseded this one.');
    return;
  }

  const prs = await call(rest + '/pulls?state=all&base=main&head=' + encodeURIComponent('true-line:' + branch));
  requireState(prs.length <= 1 && !prs.some(pr => pr.state !== 'open'), 'The release PR has already been closed');
  let releaseHead = (await ref('heads/' + branch))?.object.sha;
  if (!releaseHead) {
    requireState(prs.length === 0, 'Release PR lost its branch');
    await call(rest + '/git/refs', { method: 'POST', data: { ref: 'refs/heads/' + branch, sha } });
    releaseHead = sha;
  }
  if (releaseHead === sha) {
    requireState(prs.length === 0, 'Existing release PR was reset');
    const result = await call('/graphql', { method: 'POST', data: { query: mutation, variables: { input: {
      branch: { repositoryNameWithOwner: repo, branchName: branch }, expectedHeadOid: sha,
      message: { headline: title }, fileChanges: { additions },
    } } } });
    requireState(!result.errors && result.data?.createCommitOnBranch?.commit?.oid, 'The release commit could not be created');
    releaseHead = result.data.createCommitOnBranch.commit.oid;
  }
  const commit = await call(rest + '/commits/' + releaseHead);
  requireState(commit.parents.length === 1 && commit.parents[0].sha === sha &&
    commit.commit.tree.sha === tree && commit.commit.message === title && commit.commit.verification.verified === true &&
    commit.author?.login === bot,
    'The existing release head differs from the verified, signed release commit; leaving it intact');
  if (prs.length) {
    requireState(prs[0].head.sha === releaseHead && prs[0].head.repo.full_name === repo && prs[0].user.login === bot, 'Release PR head or author changed');
    console.log(prs[0].html_url);
    return;
  }
  const pr = await call(rest + '/pulls', { method: 'POST', data: {
    head: branch, base: 'main', title, body: 'Pins the verified signed Machine ' + tag +
      ' draft built from `' + sha + '`. The release changes are ready for owner review.',
  } });
  console.log(pr.html_url);
}

// The workflow only checks out its own protected-main SHA. Fetch main by
// its fixed ref, then treat the event SHA as data until both commits match.
function eligibleVersion(sha) {
  git('fetch', '--quiet', '--no-tags', 'origin', 'refs/heads/main');
  const main = git('rev-parse', 'FETCH_HEAD');
  requireState(git('merge-base', sha, main) === sha, 'The Sign commit is outside main history');
  const version = git('show', sha + ':.github/machine-release-version');
  assert.match(version, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
  if (git('ls-remote', 'origin', 'refs/tags/v' + version)) {
    console.error('This release has already been tagged.');
    return '';
  }
  if (main !== sha) {
    const latest = git('show', main + ':.github/machine-release-version');
    requireState(latest !== version, 'Main changed after Sign for v' + version +
      '. Merge a new reviewed version request to rebuild and sign current main.');
    console.error('A new release request superseded this one.');
    return '';
  }
  assert.equal(main, process.env.GITHUB_SHA, 'Signing SHA must equal the trusted workflow checkout');
  return version;
}

async function main() {
  const [operation, sha, dir] = process.argv.slice(2);
  assert.equal(process.env.GITHUB_REPOSITORY, repo);
  assert.match(sha, /^[0-9a-f]{40}$/);
  assert.equal(git('rev-parse', 'HEAD'), process.env.GITHUB_SHA, 'Expected the trusted workflow checkout');
  if (operation === 'eligible-version') {
    console.log(eligibleVersion(sha));
    return;
  }
  if (operation === 'download-owner') {
    const version = (await readFile('VERSION', 'utf8')).trim();
    assert.match(version, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
    assert.equal(git('merge-base', 'HEAD', sha), sha, 'Signing SHA must be in release history');
    assert.equal(git('show', sha + ':.github/machine-release-version'), version);
    assert.deepEqual(git('diff', '--name-only', sha, 'HEAD').split('\n').sort(), files,
      'Only release metadata may differ from the signing tree');
    return downloadOwner(version, sha, dir);
  }
  assert.equal(sha, process.env.GITHUB_SHA, 'Expected Sign at the trusted workflow checkout');
  const version = (await readFile('.github/machine-release-version', 'utf8')).trim();
  assert.match(version, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
  if (operation === 'download') return download(version, sha, dir);
  assert.equal(operation, 'open-pr');
  assert.equal(process.env.APP_SLUG + '[bot]', bot);
  assert.deepEqual(git('diff', '--name-only', 'HEAD').split('\n').sort(), files);
  git('add', '--', ...files);
  const tree = git('write-tree');
  const additions = await Promise.all(files.map(async path => ({ path, contents: (await readFile(path)).toString('base64') })));
  await openReleasePR({ version, sha, tree, additions });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
