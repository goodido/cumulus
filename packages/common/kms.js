'use strict';

const { encrypt, decryptBase64String } = require('./aws-client-KMS');

class KMSDecryptionFailed extends Error {
  constructor(message) {
    super(message);
    this.name = 'KMSDecryptionFailed';
  }
}

class KMS {
  static encrypt(text, kmsId) {
    return encrypt(kmsId, text);
  }

  static async decrypt(text) {
    try {
      return await decryptBase64String(text);
    } catch (err) {
      if (err.name === 'InvalidCiphertextException') {
        throw new KMSDecryptionFailed(
          'Decrypting the secure text failed. The provided text is invalid'
        );
      }

      throw err;
    }
  }
}

module.exports = {
  KMS,
  KMSDecryptionFailed
};
