'use strict';

const path = require('path');
const test = require('ava');
const KMS = require('@cumulus/common/aws-client-KMS');
const {
  dynamodb, dynamodbDocClient, kms, s3PutFile, recursivelyDeleteS3Bucket, s3
} = require('@cumulus/common/aws');
const { randomString } = require('@cumulus/common/test-utils');
const { S3KeyPairProvider } = require('@cumulus/common/key-pair-provider');
const Provider = require('../../models/providers');
const { fakeProviderFactory } = require('../../lib/testUtils');
const { handler } = require('../../lambdas/providerSecretsMigration');

test.before(async () => {
  const createKeyResponse = await kms().createKey({}).promise();
  process.env.providersKeyId = createKeyResponse.KeyMetadata.KeyId;

  process.env.system_bucket = randomString();
  await s3().createBucket({ Bucket: process.env.system_bucket }).promise();

  process.env.stackName = randomString();

  await s3PutFile(
    process.env.system_bucket,
    `${process.env.stackName}/crypto/public.pub`,
    path.join(__dirname, 'fixtures', 'public.pub')
  );

  await s3PutFile(
    process.env.system_bucket,
    `${process.env.stackName}/crypto/private.pem`,
    path.join(__dirname, 'fixtures', 'private.pem')
  );
});

test.beforeEach(async (t) => {
  process.env.ProvidersTable = randomString();

  await dynamodb().createTable({
    TableName: process.env.ProvidersTable,
    AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
    KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
    ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
  }).promise();

  t.context.providerModel = new Provider();
});

test.afterEach.always(async () => {
  await dynamodb().deleteTable({
    TableName: process.env.ProvidersTable
  }).promise();
});

test.after.always(async () => {
  await recursivelyDeleteS3Bucket(process.env.system_bucket);
});

test.serial('A provider without a username or password is properly updated', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory({
    protocol: 'ftp',
    encrypted: false
  });

  delete provider.username;
  delete provider.password;

  await dynamodbDocClient().put({
    TableName: process.env.ProvidersTable,
    Item: { ...provider, createdAt: Date.now() }
  }).promise();

  await handler();

  const fetchedProvider = await providerModel.get({ id: provider.id });
  t.is(fetchedProvider.encrypted, undefined);
  t.is(await fetchedProvider.username, undefined);
  t.is(await fetchedProvider.password, undefined);
});

test.serial('Unencrypted provider credentials are encrypted using KMS', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory({
    protocol: 'ftp',
    encrypted: false,
    username: 'my-username',
    password: 'my-password'
  });

  await dynamodbDocClient().put({
    TableName: process.env.ProvidersTable,
    Item: { ...provider, createdAt: Date.now() }
  }).promise();

  await handler();

  const fetchedProvider = await providerModel.get({ id: provider.id });
  t.is(fetchedProvider.encrypted, undefined);
  t.is(await KMS.decryptBase64String(fetchedProvider.username), 'my-username');
  t.is(await KMS.decryptBase64String(fetchedProvider.password), 'my-password');
});

test.serial('Credentials encrypted using KMS are not changed', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory({
    protocol: 'ftp',
    username: 'my-username',
    password: 'my-password'
  });

  await providerModel.create(provider);

  await handler();

  const fetchedProvider = await providerModel.get({ id: provider.id });
  t.is(fetchedProvider.encrypted, undefined);
  t.is(await KMS.decryptBase64String(fetchedProvider.username), 'my-username');
  t.is(await KMS.decryptBase64String(fetchedProvider.password), 'my-password');
});

test.serial('Credentials encrypted using S3KeyPairProvider are updated to KMS', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory({
    protocol: 'ftp',
    encrypted: true,
    username: await S3KeyPairProvider.encrypt('my-username'),
    password: await S3KeyPairProvider.encrypt('my-password')
  });

  await dynamodbDocClient().put({
    TableName: process.env.ProvidersTable,
    Item: { ...provider, createdAt: Date.now() }
  }).promise();

  await handler();

  const fetchedProvider = await providerModel.get({ id: provider.id });
  t.is(fetchedProvider.encrypted, undefined);
  t.is(await KMS.decryptBase64String(fetchedProvider.username), 'my-username');
  t.is(await KMS.decryptBase64String(fetchedProvider.password), 'my-password');
});

test.serial('Empty, Plaintext, KMS-encrypted, and S3KeyPairProvider-encrypted credentials are all handled properly', async (t) => {
  const { providerModel } = t.context;

  // Create and store the provider without credentials
  const uncredentialedProvider = fakeProviderFactory({
    protocol: 'ftp',
    encrypted: false
  });

  delete uncredentialedProvider.username;
  delete uncredentialedProvider.password;

  await dynamodbDocClient().put({
    TableName: process.env.ProvidersTable,
    Item: { ...uncredentialedProvider, createdAt: Date.now() }
  }).promise();

  // Create and store the plaintext provider
  const ptProvider = fakeProviderFactory({
    protocol: 'ftp',
    encrypted: false,
    username: 'my-username',
    password: 'my-password'
  });

  await dynamodbDocClient().put({
    TableName: process.env.ProvidersTable,
    Item: { ...ptProvider, createdAt: Date.now() }
  }).promise();

  // Create and store the KMS provider
  const kmsProvider = fakeProviderFactory({
    protocol: 'ftp',
    username: 'my-username',
    password: 'my-password'
  });

  await providerModel.create(kmsProvider);

  // Create and store the S3KeyPairProvider provider
  const username = await S3KeyPairProvider.encrypt('my-username');
  const password = await S3KeyPairProvider.encrypt('my-password');

  const s3EncryptedProvider = fakeProviderFactory({
    protocol: 'ftp',
    encrypted: true,
    username,
    password
  });

  await dynamodbDocClient().put({
    TableName: process.env.ProvidersTable,
    Item: { ...s3EncryptedProvider, createdAt: Date.now() }
  }).promise();

  await handler();

  // Make sure it all worked
  const fetchedUncredentialedProvider = await providerModel.get({ id: uncredentialedProvider.id });
  t.is(fetchedUncredentialedProvider.encrypted, undefined);
  t.is(await fetchedUncredentialedProvider.username, undefined);
  t.is(await fetchedUncredentialedProvider.password, undefined);

  const fetchedPtProvider = await providerModel.get({ id: ptProvider.id });
  t.is(fetchedPtProvider.encrypted, undefined);
  t.is(await KMS.decryptBase64String(fetchedPtProvider.username), 'my-username');
  t.is(await KMS.decryptBase64String(fetchedPtProvider.password), 'my-password');

  const fetchedKmsProvider = await providerModel.get({ id: kmsProvider.id });
  t.is(fetchedKmsProvider.encrypted, undefined);
  t.is(await KMS.decryptBase64String(fetchedKmsProvider.username), 'my-username');
  t.is(await KMS.decryptBase64String(fetchedKmsProvider.password), 'my-password');

  const fetchedS3Provider = await providerModel.get({ id: s3EncryptedProvider.id });
  t.is(fetchedS3Provider.encrypted, undefined);
  t.is(await KMS.decryptBase64String(fetchedS3Provider.username), 'my-username');
  t.is(await KMS.decryptBase64String(fetchedS3Provider.password), 'my-password');
});

test.serial('A provider with an un-decryptable encrypted password causes an exception to be thrown', async (t) => {
  const provider = fakeProviderFactory({
    protocol: 'ftp',
    encrypted: true,
    username: 'blah',
    password: 'blah'
  });

  await dynamodbDocClient().put({
    TableName: process.env.ProvidersTable,
    Item: { ...provider, createdAt: Date.now() }
  }).promise();

  await t.throwsAsync(handler());
});
