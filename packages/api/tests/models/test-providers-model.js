'use strict';

const test = require('ava');
const { kms, recursivelyDeleteS3Bucket, s3 } = require('@cumulus/common/aws');
const { randomString } = require('@cumulus/common/test-utils');
const KMS = require('@cumulus/common/aws-client-KMS');

const schemas = require('../../models/schemas');
const {
  fakeProviderFactory,
  fakeRuleFactoryV2
} = require('../../lib/testUtils');
const { Manager, Provider, Rule } = require('../../models');
const { AssociatedRulesError } = require('../../lib/errors');

let manager;
let ruleModel;
test.before(async (t) => {
  const createKeyResponse = await kms().createKey({}).promise();
  process.env.providersKeyId = createKeyResponse.KeyMetadata.KeyId;

  process.env.ProvidersTable = randomString();

  manager = new Manager({
    tableName: process.env.ProvidersTable,
    tableHash: { name: 'id', type: 'S' },
    schema: schemas.provider
  });

  await manager.createTable();

  process.env.RulesTable = randomString();
  ruleModel = new Rule();
  await ruleModel.createTable();

  process.env.system_bucket = randomString();
  await s3().createBucket({ Bucket: process.env.system_bucket }).promise();

  process.env.stackName = randomString();

  t.context.providerModel = new Provider();
});

test.after.always(async () => {
  await manager.deleteTable();
  await ruleModel.deleteTable();
  await recursivelyDeleteS3Bucket(process.env.system_bucket);
});


test('Provider.create() stores a provider without login credentials', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory();
  delete provider.username;
  delete provider.password;

  await providerModel.create(provider);

  const fetchedProvider = await providerModel.get({ id: provider.id });
  t.is(fetchedProvider.username, undefined);
  t.is(fetchedProvider.password, undefined);
});

test('Provider.create() encrypts login credentials', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory({
    username: 'my-username',
    password: 'my-password'
  });

  await providerModel.create(provider);

  const fetchedProvider = await providerModel.get({ id: provider.id });
  t.is(await KMS.decryptBase64String(fetchedProvider.username), 'my-username');
  t.is(await KMS.decryptBase64String(fetchedProvider.password), 'my-password');
});

test('Provider.create() throws a ValidationError if an invalid host is used', async (t) => {
  const { providerModel } = t.context;

  try {
    await providerModel.create(
      fakeProviderFactory({ host: 'http://www.example.com' })
    );

    t.fail('Expected an exception');
  } catch (err) {
    t.is(err.name, 'ValidationError');
  }
});

test('Provider.update() adds login credentials', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory();
  delete provider.username;
  delete provider.password;

  await providerModel.create(provider);

  await providerModel.update(
    { id: provider.id },
    { username: 'my-username', password: 'my-password' }
  );

  const fetchedProvider = await providerModel.get({ id: provider.id });
  t.is(await KMS.decryptBase64String(fetchedProvider.username), 'my-username');
  t.is(await KMS.decryptBase64String(fetchedProvider.password), 'my-password');
});

test('Provider.update() updates login credentials', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory({
    username: 'first-username',
    password: 'first-password'
  });

  await providerModel.create(provider);

  await providerModel.update(
    { id: provider.id },
    { username: 'second-username', password: 'second-password' }
  );

  const fetchedProvider = await providerModel.get({ id: provider.id });
  t.is(await KMS.decryptBase64String(fetchedProvider.username), 'second-username');
  t.is(await KMS.decryptBase64String(fetchedProvider.password), 'second-password');
});

test('Provider.update() removes login credentials', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory({
    username: 'first-username',
    password: 'first-password'
  });

  await providerModel.create(provider);

  await providerModel.update(
    { id: provider.id },
    {},
    ['username', 'password']
  );

  const fetchedProvider = await providerModel.get({ id: provider.id });
  t.is(fetchedProvider.username, undefined);
  t.is(fetchedProvider.password, undefined);
});

test('Provider.update() throws a ValidationError if an invalid host is used', async (t) => {
  const { providerModel } = t.context;

  const provider = fakeProviderFactory();
  await providerModel.create(provider);

  try {
    await providerModel.update(
      { id: provider.id },
      { host: 'http://www.example.com' }
    );

    t.fail('Expected an exception');
  } catch (err) {
    t.is(err.name, 'ValidationError');
  }
});

test('Provider.delete() throws an exception if the provider has associated rules', async (t) => {
  const { providerModel } = t.context;

  const providerId = randomString();
  await manager.create(fakeProviderFactory({ id: providerId }));

  const rule = fakeRuleFactoryV2({
    provider: providerId,
    rule: {
      type: 'onetime'
    }
  });

  // The workflow message template must exist in S3 before the rule can be created
  await Promise.all([
    s3().putObject({
      Bucket: process.env.system_bucket,
      Key: `${process.env.stackName}/workflows/${rule.workflow}.json`,
      Body: JSON.stringify({})
    }).promise(),
    s3().putObject({
      Bucket: process.env.system_bucket,
      Key: `${process.env.stackName}/workflow_template.json`,
      Body: JSON.stringify({})
    }).promise()
  ]);

  await ruleModel.create(rule);

  try {
    await providerModel.delete({ id: providerId });
    t.fail('Expected an exception to be thrown');
  } catch (err) {
    t.true(err instanceof AssociatedRulesError);
    t.is(err.message, 'Cannot delete a provider that has associated rules');
    t.deepEqual(err.rules, [rule.name]);
  }
});

test('Provider.delete() deletes a provider', async (t) => {
  const { providerModel } = t.context;

  const providerId = randomString();
  await manager.create(fakeProviderFactory({ id: providerId }));

  await providerModel.delete({ id: providerId });

  t.false(await manager.exists({ id: providerId }));
});

test('Provider.exists() returns true when a record exists', async (t) => {
  const { providerModel } = t.context;

  const id = randomString();

  await manager.create(fakeProviderFactory({ id }));

  t.true(await providerModel.exists(id));
});

test('Provider.exists() returns false when a record does not exist', async (t) => {
  const { providerModel } = t.context;

  t.false(await providerModel.exists(randomString()));
});
