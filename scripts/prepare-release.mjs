// Release metadata for protected main and verified Machine draft downloads.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const repo = 'true-line/agent-bot-machine';
const bot = 'trueline-chores-dumb[bot]';
const skill = 'skills/managed-machine/SKILL.md';
const api = 'https://api.github.com';
const rest = '/repos/' + repo;
const platformArchives = ['darwin_arm64.tar.gz', 'linux_amd64.tar.gz', 'linux_arm64.tar.gz', 'windows_amd64.zip', 'windows_arm64.zip'];
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
const machineFormula = () => execFileSync('bash', ['scripts/machine-homebrew-formula', '.'], { encoding: 'utf8' }).trim();
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
  requireState(draft?.draft === true && draft.tag_name === 'v' + version && draft.target_commitish === sha,
    'The release must be a draft for this exact Sign commit and version');
  const expected = ['SHA256SUMS', ...platformArchives.map(s => 'managed-machine_' + version + '_' + s)].sort();
  assert.deepEqual(draft.assets.map(a => a.name).sort(), expected, 'Unexpected draft asset set');
  for (const asset of draft.assets) {
    requireState(Number.isSafeInteger(asset.id) && asset.id > 0 && asset.state === 'uploaded' &&
      /^sha256:[0-9a-f]{64}$/.test(asset.digest), 'Missing uploaded asset or digest for ' + asset.name);
  }
}

export async function download(version, sha, dir, call = request) {
  // Draft releases can have no tag ref yet. The published-by-tag endpoint
  // cannot reliably see them; use the authenticated releases collection.
  let draft;
  for (let page = 1; !draft; page++) {
    const batch = await call(rest + '/releases?per_page=100&page=' + page);
    draft = batch.find(r => r.tag_name === 'v' + version);
    if (!draft && batch.length < 100) break;
  }
  validateDraft(draft, version, sha);
  await mkdir(dir);
  for (const asset of draft.assets) {
    const bytes = await call(rest + '/releases/assets/' + asset.id, { binary: true });
    assert.equal('sha256:' + createHash('sha256').update(bytes).digest('hex'), asset.digest, asset.name);
    await writeFile(join(dir, asset.name), bytes, { flag: 'wx' });
  }
}

const mutation = `mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid } }
}`;

export async function openReleasePR({version, sha, tree, additions, tap = false}, call = request) {
  const tag = 'v' + version;
  const branch = (tap ? 'homebrew/' : 'release/') + tag;
  const title = (tap ? 'Pin Homebrew to ' : 'Release ') + tag;
  const ref = name => call(rest + '/git/ref/' + name, { optional: true });
  const head = await ref('heads/main');
  if (!tap && await ref('tags/' + tag)) {
    console.log('The release tag already exists; no release branch changes.');
    return;
  }
  if (head?.object.sha !== sha) {
    requireState(!tap, 'Main advanced while preparing the tap update. Dispatch Homebrew synchronization on current main.');
    console.log('A newer main push owns release preparation.');
    return;
  }

  const prs = await call(rest + '/pulls?state=all&base=main&head=' + encodeURIComponent('true-line:' + branch));
  requireState(prs.length <= 1 && !prs.some(pr => pr.state !== 'open'), 'The release PR has already been closed');
  let releaseHead = (await ref('heads/' + branch))?.object.sha;
  if (prs.length) {
    const pr = prs[0];
    requireState(pr.head.sha === releaseHead && pr.head.repo.full_name === repo && pr.user.login === bot,
      'Release PR head or author changed');
    const comparison = await call(rest + '/compare/' + releaseHead + '...' + sha);
    if (comparison.ahead_by > 0) {
      await call(rest + '/pulls/' + pr.number + '/update-branch', {
        method: 'PUT', data: {expected_head_sha: releaseHead},
      });
    }
    console.log(pr.html_url);
    return;
  }
  if (!releaseHead) {
    await call(rest + '/git/refs', { method: 'POST', data: { ref: 'refs/heads/' + branch, sha } });
    releaseHead = sha;
  }
  if (releaseHead === sha) {
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
  const pr = await call(rest + '/pulls', { method: 'POST', data: {
    head: branch, base: 'main', title,
    body: tap ? 'Pin Homebrew to the verified signed archive published with ' + tag + '.' :
      'Merging this version PR starts signing Machine ' + tag + ' for macOS, Linux and Windows.',
  } });
  console.log(pr.html_url);
}

const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
function parts(version) {
  assert.match(version, semver);
  return version.split('.').map(n => BigInt(n));
}
function newer(a, b) {
  const left = parts(a);
  const right = parts(b);
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return left[i] > right[i];
  }
  return false;
}
function patch(version) {
  const [major, minor, revision] = parts(version);
  return [major, minor, revision + 1n].join('.');
}

export function skillForVersion(text, version) {
  const range = /^(  qwts-versions: ">=([0-9.]+) <)([0-9.]+)(")$/m;
  const validated = /^(  qwts-validated: ")[0-9.]+(")$/m;
  assert.ok(range.test(text) && validated.test(text), 'Expected bounded Machine skill metadata');
  return text.replace(range, (_, start, lower, upper, end) => {
    assert.ok(!newer(lower, version), 'Version predates the skill');
    return start + (newer(upper, version) ? upper : patch(version)) + end;
  }).replace(validated, (_, start, end) => start + version + end);
}

export function publishedPin(old, pinned, version, digest, published) {
  // Apply only version and checksum fields to current main. Never copy Ruby code from an asset.
  const oldDigest = old.match(/^    sha256 "([0-9a-f]{64})"$/m)?.[1];
  assert.ok(oldDigest);
  const rendered = old.replaceAll('v' + pinned + '"', 'v' + version + '"')
    .replace('  version "' + pinned + '"', '  version "' + version + '"')
    .replace('/v' + pinned + '/managed-machine_' + pinned + '_', '/v' + version + '/managed-machine_' + version + '_')
    .replace('    sha256 "' + oldDigest + '"', '    sha256 "' + digest.slice(7) + '"');
  // Prove the asset pins these same values even if other formula code advanced on main.
  for (const line of rendered.split('\n').filter(l => /^\s*(tag:|version "|sha256 "|url ".*releases\/download)/.test(l))) {
    assert.ok(published.split('\n').includes(line), 'Published formula disagrees: ' + line);
  }
  return rendered;
}

async function prepare(tap) {
  const sha = process.env.GITHUB_SHA;
  const current = git('show', 'HEAD:VERSION');
  if (tap) {
    const formula = machineFormula();
    const release = await request(rest + '/releases/latest');
    const version = release.tag_name.slice(1);
    assert.match(version, semver);
    assert.equal(release.tag_name, 'v' + version);
    const old = await readFile(formula, 'utf8');
    const pinned = old.match(/^  version "([0-9.]+)"$/m)?.[1];
    if (!newer(version, pinned)) return;
    assert.equal(git('rev-parse', release.tag_name + '^{commit}'), git('merge-base', release.tag_name, sha));
    const asset = release.assets.find(a => a.name === basename(formula));
    assert.ok(asset?.state === 'uploaded', 'Published formula asset missing');
    const bytes = await request(rest + '/releases/assets/' + asset.id, {binary: true});
    assert.equal('sha256:' + createHash('sha256').update(bytes).digest('hex'), asset.digest);
    const archive = release.assets.find(a => a.name === 'managed-machine_' + version + '_darwin_arm64.tar.gz');
    assert.match(archive?.digest ?? '', /^sha256:[0-9a-f]{64}$/);
    const rendered = publishedPin(old, pinned, version, archive.digest, bytes.toString('utf8'));
    await writeFile(formula, rendered);
    return version;
  }
  if (process.env.EVENT === 'push') {
    const changed = git('diff', '--name-only', process.env.BEFORE, sha).split('\n');
    if (changed.includes('VERSION') && changed.every(p => p === 'VERSION' || p === skill)) return;
  }
  const hint = git('show', 'HEAD:.github/machine-release-version');
  const version = newer(hint, current) ? hint : patch(current);
  await writeFile('VERSION', version + '\n');
  await writeFile(skill, skillForVersion(await readFile(skill, 'utf8'), version));
  return version;
}

async function main() {
  const [operation] = process.argv.slice(2);
  const sha = process.env.GITHUB_SHA;
  assert.equal(process.env.GITHUB_REPOSITORY, repo);
  assert.match(sha, /^[0-9a-f]{40}$/);
  assert.equal(git('rev-parse', 'HEAD'), sha, 'Expected protected workflow checkout');
  const tap = process.env.EVENT === 'workflow_run' || process.env.OPERATION === 'homebrew';
  if (operation === 'prepare') {
    const version = await prepare(tap);
    if (version) await appendFile(process.env.GITHUB_OUTPUT, 'version=' + version + '\n');
    return;
  }
  assert.equal(operation, 'open-pr');
  assert.equal(process.env.APP_SLUG + '[bot]', bot);
  const version = process.env.VERSION;
  assert.match(version, semver);
  const files = tap ? [machineFormula()] : ['VERSION', skill];
  assert.deepEqual(git('diff', '--name-only', 'HEAD').split('\n').sort(), files);
  git('add', '--', ...files);
  const tree = git('write-tree');
  const additions = await Promise.all(files.map(async path => ({path, contents: (await readFile(path)).toString('base64')})));
  await openReleasePR({version, sha, tree, additions, tap});
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
