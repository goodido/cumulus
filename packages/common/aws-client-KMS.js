'use strict';

const { kms } = require('./aws');

const encrypt = (KeyId, Plaintext) =>
  kms().encrypt({ KeyId, Plaintext }).promise()
    .then(({ CiphertextBlob }) => CiphertextBlob.toString('base64'));

const decryptBase64String = (ciphertext) =>
  kms().decrypt({
    CiphertextBlob: Buffer.from(ciphertext, 'base64')
  }).promise()
    .then(({ Plaintext }) => Plaintext.toString());

module.exports = {
  decryptBase64String,
  encrypt
};
