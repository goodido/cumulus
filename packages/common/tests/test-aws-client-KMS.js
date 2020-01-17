'use strict';

const test = require('ava');
const { kms } = require('../aws');
const { encrypt, decryptBase64String } = require('../aws-client-KMS');

test.before(async (t) => {
  const createKeyResponse = await kms().createKey({}).promise();
  t.context.KeyId = createKeyResponse.KeyMetadata.KeyId;
});

test('encrypt() properly encrypts a value', async (t) => {
  const ciphertext = await encrypt(t.context.KeyId, 'asdf');

  const plaintext = await kms().decrypt({
    CiphertextBlob: Buffer.from(ciphertext, 'base64')
  }).promise()
    .then(({ Plaintext }) => Plaintext.toString());

  t.is(plaintext, 'asdf');
});

test('decryptBase64String() properly decrypts a value', async (t) => {
  const { KeyId } = t.context;

  const ciphertext = await kms().encrypt({ KeyId, Plaintext: 'asdf' }).promise()
    .then(({ CiphertextBlob }) => CiphertextBlob.toString('base64'));

  const plaintext = await decryptBase64String(ciphertext);
  t.is(plaintext, 'asdf');
});
