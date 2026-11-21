// Independent transport verifier for a disposable real dedicated role. No
// enrollment proof, private key or signed response is printed or persisted.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { userInfo } from 'node:os';
import { join } from 'node:path';

const [operation, socket, epoch, expectedThumbprint] = process.argv.slice(2);
const account = userInfo();
assert.equal(process.env.GITHUB_ACTIONS, 'true');
assert.equal(account.username, '_agent-bot-hq');
assert.match(epoch, /^[0-9a-f]{64}$/);
const dir = join(account.homedir, '.config', 'agent-machine');
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), readFileSync(join(dir,'client.key'))]), format:'der', type:'pkcs8' });
const machine = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100','hex'), readFileSync(join(dir,'daemon.pub'))]), format:'der', type:'spki' });
const publicKey = readFileSync(join(dir,'client.pub')).toString('base64');
assert.equal(createPublicKey(privateKey).export({type:'spki',format:'der'}).subarray(-32).toString('base64'),publicKey);
const option = operation === 'identity' ? 'identity' : 'enrollment-proof';
const stream = connect({path:socket});
stream.setTimeout(4000,()=>stream.destroy(new Error('fixture socket deadline')));
if (operation === 'outage') {
  await assert.rejects(once(stream,'connect'), error => ['ENOENT','ECONNREFUSED'].includes(error.code));
  process.exit(0);
}
await once(stream,'connect');
if (operation === 'deferred') {
  process.stdout.write('connected\n');
  const [input] = await once(process.stdin,'data');
  assert.equal(input.toString().trim(),'send');
  process.stdin.pause();
}
const nonce = randomBytes(16).toString('base64url');
const timestamp = Math.floor(Date.now()/1000);
const components = ['hq-device','',option,'','','','','',String(timestamp),nonce];
const request = {verb:'hq-device',option,public_key:publicKey,timestamp,nonce};
if (option !== 'identity') { request.hq_epoch=epoch; components.push('hq_epoch',epoch); }
request.signature=sign(null,Buffer.from(components.join('\n')),privateKey).toString('base64');
stream.write(JSON.stringify(request)+'\n');
let line='';
for await(const chunk of stream) { line+=chunk; assert.ok(line.length<=65536); }
assert.equal(line.indexOf('\n'),line.length-1);
const response=JSON.parse(line);
assert.equal(response.request_nonce,nonce);
assert.ok(Math.abs(Math.floor(Date.now()/1000)-response.timestamp)<=30);
// These two successful body contracts contain only public base64/ASCII fields
// and integers, emitted by Go without whitespace or escaped string contents.
const payload=[String(response.ok),response.diagnostic??'',response.message??'',response.state??'',response.body?JSON.stringify(response.body):'',String(response.timestamp),response.nonce,nonce].join('\n');
assert.ok(verify(null,Buffer.from(payload),machine,Buffer.from(response.signature,'base64')));
if (operation==='deferred'||operation==='refused') {
  assert.equal(response.ok,false);
  assert.equal(response.diagnostic,'MM_DAEMON_PEER_REFUSED');
  assert.equal(Object.hasOwn(response,'body'),false);
} else {
  assert.equal(response.ok,true);
  const {jwk,thumbprint,key_storage,hq_epoch,proof}=response.body;
  assert.equal(hq_epoch,epoch);
  assert.equal(key_storage,'hardware');
  assert.equal(jwk.kty,'EC'); assert.equal(jwk.crv,'P-256');
  assert.equal(thumbprint,createHash('sha256').update(JSON.stringify({crv:jwk.crv,kty:jwk.kty,x:jwk.x,y:jwk.y})).digest('base64url'));
  if(operation==='identity') {
    assert.equal(response.state,'identity'); assert.equal(proof,undefined);
    console.log(thumbprint);
  } else {
    assert.equal(operation,'prove'); assert.equal(response.state,'proved');
    assert.ok(thumbprint === expectedThumbprint, 'enrollment proof used a different device');
    const [header,claims,sig]=proof.split('.');
    const parsed=part=>JSON.parse(Buffer.from(part,'base64url'));
    assert.deepEqual(parsed(header),{alg:'ES256',typ:'ab-enroll+jwt',jwk});
    const body=parsed(claims);
    assert.equal(body.aud,'https://agents.true-line.ai/oauth/device_authorization');
    assert.ok(Math.abs(body.iat-timestamp)<=30);
    const jti = Buffer.from(body.jti, 'base64url');
    assert.ok(jti.length === 16 && jti.toString('base64url') === body.jti, 'invalid enrollment proof ID');
    assert.ok(verify('sha256',Buffer.from(header+'.'+claims),{key:createPublicKey({key:jwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(sig,'base64url')));
    // The shell compares only these digests so a previously issued proof cannot satisfy the restart check.
    console.log(createHash('sha256').update(jti).digest('hex'));
  }
}
