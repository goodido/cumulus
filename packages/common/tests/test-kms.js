'use strict';

const test = require('ava');
const { kms } = require('../aws');
const { KMS, KMSDecryptionFailed } = require('../kms');

test.before(async (t) => {
  const createResponse = await kms().createKey({}).promise();
  t.context.KeyId = createResponse.KeyMetadata.KeyId;
});

test('encrypt() returns the correct ciphertext', async (t) => {
  const { KeyId } = t.context;

  const ct = await KMS.encrypt('hello world', KeyId);

  const pt = await kms().decrypt({
    CiphertextBlob: Buffer.from(ct, 'base64')
  }).promise()
    .then(({ Plaintext }) => Plaintext.toString());

  t.is(pt, 'hello world');
});

test('decrypt() returns the correct plaintext', async (t) => {
  const { KeyId } = t.context;

  const ciphertext = await kms().encrypt({
    KeyId, Plaintext: 'hello world'
  }).promise()
    .then(({ CiphertextBlob }) => CiphertextBlob.toString('base64'));

  const plaintext = await KMS.decrypt(ciphertext);

  t.is(plaintext, 'hello world');
});

test('decrypt() throws a KMSDecryptionFailed exception if the ciphertext was invalid', async (t) => {
  await t.throwsAsync(
    KMS.decrypt('asdf'),
    { instanceOf: KMSDecryptionFailed }
  );
});
