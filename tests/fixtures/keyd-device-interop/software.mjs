// The standalone fixture executes this module with Node's --eval. Its software
// key references are synthetic and remain in the fixture's private directory.
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';

const [operation] = process.argv.slice(1);
const input = JSON.parse(readFileSync(0, 'utf8'));
if (operation === 'create') {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  process.stdout.write(privateKey.export({ format: 'der', type: 'pkcs8' }));
} else {
  const key = createPrivateKey({
    key: Buffer.from(input.reference, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
  if (operation === 'public') {
    const { x, y } = createPublicKey(key).export({ format: 'jwk' });
    process.stdout.write(Buffer.concat([
      Buffer.from([4]), Buffer.from(x, 'base64url'), Buffer.from(y, 'base64url'),
    ]));
  } else if (operation === 'sign') {
    process.stdout.write(sign('sha256', Buffer.from(input.message, 'base64'), {
      key,
      dsaEncoding: 'ieee-p1363',
    }));
  } else {
    process.exitCode = 1;
  }
}
