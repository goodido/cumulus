'use strict';

const KMS = require('@cumulus/common/aws-client-KMS');
const { dynamodbDocClient } = require('@cumulus/common/aws');
const { S3KeyPairProvider } = require('@cumulus/common/key-pair-provider');
const { isNil } = require('@cumulus/common/util');
const Provider = require('../models/providers');

const getDecryptedField = async (provider, field) => {
  if (isNil(provider[field])) return null;
  if (provider.encrypted === false) return provider[field];

  return KMS.decryptBase64String(provider[field])
    .catch(() => S3KeyPairProvider.decrypt(provider[field]));
};

const migrateProvider = async (provider) => {
  // No credentials, and `encrypted` has already been removed
  if (
    isNil(provider.username)
    && isNil(provider.password)
    && provider.encrypted === undefined
  ) return;

  const username = await getDecryptedField(provider, 'username');
  const password = await getDecryptedField(provider, 'password');

  const providerModel = new Provider();
  await providerModel.update(
    { id: provider.id },
    { username, password },
    ['encrypted']
  );
};

const handler = async () => {
  const scanResponse = await dynamodbDocClient().scan({
    TableName: process.env.ProvidersTable
  }).promise();

  await Promise.all(scanResponse.Items.map(migrateProvider));
};

module.exports = { handler };
