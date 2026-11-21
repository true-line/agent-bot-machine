// Disposable loopback issuer. Its signing key stays in this admin process.
import { chmodSync, renameSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import assert from 'node:assert/strict';
const [source, dir] = process.argv.slice(2);
assert.equal(process.env.GITHUB_ACTIONS, 'true');
assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
const { fakeIdentityService } = await import(pathToFileURL(join(source, 'tests/identity-service-fixture.mjs')));
const origin = 'https://agents.true-line.ai';
const server = await fakeIdentityService({ issuer: origin });
assert.equal(new URL(server.url).hostname, '127.0.0.1');
// The private fixture automatically approves only its own disposable grants.
const timer = setInterval(() => server.decide('approved'), 20);
const config = join(dir, 'hq-issuer.json');
const temporary = config + '.tmp';
writeFileSync(temporary, JSON.stringify({ url: server.url, key: server.key }), { mode: 0o644, flag: 'wx' });
chmodSync(temporary, 0o644);
renameSync(temporary, config);
async function stop() { clearInterval(timer); await server.close(); process.exit(0); }
process.on('SIGTERM', stop);
