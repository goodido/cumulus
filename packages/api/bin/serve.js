'use strict';

const pLimit = require('p-limit');
const { promiseS3Upload } = require('@cumulus/aws-client/S3');
const { s3 } = require('@cumulus/aws-client/services');
const { randomString, randomId, inTestMode } = require('@cumulus/common/test-utils');
const bootstrap = require('../lambdas/bootstrap');
const indexer = require('../es/indexer');
const { Search } = require('../es/search');
const models = require('../models');
const testUtils = require('../lib/testUtils');

const workflowList = testUtils.getWorkflowList();
const defaultLocalStackName = 'localrun';

async function createTable(Model, tableName) {
  try {
    const model = new Model({
      tableName,
      stackName: process.env.stackName,
      systemBucket: process.env.system_bucket
    });
    await model.createTable();
  } catch (e) {
    if (e && e.message && e.message === 'Cannot create preexisting table') {
      console.log(`${tableName} is already created`);
    } else {
      throw e;
    }
  }
}

async function populateBucket(bucket, stackName) {
  // upload workflow files
  await Promise.all(workflowList.map((obj) => promiseS3Upload({
    Bucket: bucket,
    Key: `${stackName}/workflows/${obj.name}.json`,
    Body: JSON.stringify(obj)
  })));
  // upload workflow template
  const workflow = `${stackName}/workflow_template.json`;
  await promiseS3Upload({
    Bucket: bucket,
    Key: workflow,
    Body: JSON.stringify({})
  });
}

function setTableEnvVariables(stackName) {
  const tableModels = Object
    .keys(models)
    .filter((t) => t !== 'Manager');

  // generate table names
  let tableNames = tableModels
    .map((t) => {
      let table = t;
      if (t === 'FileClass') {
        table = 'File';
      }
      return `${table}sTable`;
    });

  // set table env variables
  tableNames = tableNames.map((t) => {
    process.env[t] = `${stackName}-${t}`;
    return process.env[t];
  });

  return {
    tableModels,
    tableNames
  };
}

// check if the tables and elasticsearch indices exist
// if not create them
async function checkOrCreateTables(stackName) {
  const tables = setTableEnvVariables(stackName);

  const limit = pLimit(1);

  let i = -1;
  const promises = tables.tableModels.map((t) => limit(() => {
    i += 1;
    return createTable(
      models[t],
      tables.tableNames[i]
    );
  }));
  await Promise.all(promises);
}

function setLocalEsVariables(stackName) {
  process.env.ES_HOST = 'fakehost';
  process.env.ES_INDEX = `${stackName}-es`;
}

async function prepareServices(stackName, bucket) {
  setLocalEsVariables(stackName);
  await bootstrap.bootstrapElasticSearch(process.env.ES_HOST, process.env.ES_INDEX);
  await s3().createBucket({ Bucket: bucket }).promise();
}

function getRequiredAuthEnvVariables() {
  const authEnvVariables = process.env.FAKE_AUTH
    ? []
    : ['EARTHDATA_CLIENT_ID', 'EARTHDATA_CLIENT_PASSWORD'];
  return authEnvVariables;
}

function setAuthEnvVariables() {
  if (process.env.FAKE_AUTH) {
    process.env.EARTHDATA_CLIENT_ID = randomId('EARTHDATA_CLIENT_ID');
    process.env.EARTHDATA_CLIENT_PASSWORD = randomId('EARTHDATA_CLIENT_PASSWORD');
    process.env.EARTHDATA_BASE_URL = 'https://example.com';
  }
}

function checkEnvVariablesAreSet(moreRequiredEnvVars) {
  const authEnvVariables = getRequiredAuthEnvVariables();
  const requiredEnvVars = authEnvVariables.concat(moreRequiredEnvVars);
  requiredEnvVars.forEach((env) => {
    if (!process.env[env]) {
      throw new Error(`Environment Variable ${env} is not set!`);
    }
  });
}

async function createDBRecords(stackName, user) {
  setLocalEsVariables(stackName);
  const esClient = await Search.es(process.env.ES_HOST);
  const esIndex = process.env.ES_INDEX;
  // Resets the ES client
  await esClient.indices.delete({ index: esIndex })
    .then((response) => response.body);
  await bootstrap.bootstrapElasticSearch(process.env.ES_HOST, esIndex);

  if (user) {
    await testUtils.setAuthorizedOAuthUsers([user]);
  }

  // add collection records
  const c = testUtils.fakeCollectionFactory();
  c.name = `${stackName}-collection`;
  const cm = new models.Collection();
  const collection = await cm.create(c);
  await indexer.indexCollection(esClient, collection, esIndex);

  // add granule records
  const g = testUtils.fakeGranuleFactory();
  g.granuleId = `${stackName}-granule`;
  const gm = new models.Granule();
  const granule = await gm.create(g);
  await indexer.indexGranule(esClient, granule, esIndex);

  // add provider records
  const p = testUtils.fakeProviderFactory();
  p.id = `${stackName}-provider`;
  const pm = new models.Provider();
  const provider = await pm.create(p);
  await indexer.indexProvider(esClient, provider, esIndex);

  // add rule records
  const r = testUtils.fakeRuleFactoryV2();
  r.name = `${stackName}_rule`;
  r.workflow = workflowList[0].name;
  r.provider = `${stackName}-provider`;
  r.collection = {
    name: `${stackName}-collection`,
    version: '0.0.0'
  };
  const rm = new models.Rule();
  const rule = await rm.create(r);
  await indexer.indexRule(esClient, rule, esIndex);

  // add fake execution records
  const e = testUtils.fakeExecutionFactory();
  e.arn = `${stackName}-fake-arn`;
  const em = new models.Execution();
  const execution = await em.create(e);
  await indexer.indexExecution(esClient, execution, esIndex);

  // add pdrs records
  const pd = testUtils.fakePdrFactory();
  pd.pdrName = `${stackName}-pdr`;
  const pdm = new models.Pdr();
  await pdm.create(pd);
}

/**
 * Prepare and run the Cumulus API Express app.
 *
 * @param {string} user - A username to add as an authorized user for the API.
 * @param {string} stackName - The name of local stack. Used to prefix stack resources.
 */
async function serveApi(user, stackName = defaultLocalStackName) {
  const port = process.env.PORT || 5001;
  const requiredEnvVars = [
    'stackName',
    'system_bucket',
    'TOKEN_REDIRECT_ENDPOINT',
    'TOKEN_SECRET'
  ];

  // Set env variable to mark this as a local run of the API
  process.env.CUMULUS_ENV = 'local';

  process.env.TOKEN_REDIRECT_ENDPOINT = `http://localhost:${port}/token`;
  process.env.TOKEN_SECRET = randomString();

  if (inTestMode()) {
    // set env variables
    setAuthEnvVariables();
    process.env.system_bucket = 'localbucket';
    process.env.stackName = stackName;

    checkEnvVariablesAreSet(requiredEnvVars);

    // create tables if not already created
    await checkOrCreateTables(stackName);

    await prepareServices(stackName, process.env.system_bucket);
    await populateBucket(process.env.system_bucket, stackName);
    await createDBRecords(stackName, user);
  } else {
    checkEnvVariablesAreSet(requiredEnvVars);
    setTableEnvVariables(process.env.stackName);
  }

  console.log(`Starting server on port ${port}`);
  const { app } = require('../app'); // eslint-disable-line global-require
  app.listen(port);
}

/**
 * Prepare and run the Cumulus distribution API Express app.
 *
 * @param {string} stackName - The name of local stack. Used to prefix stack resources.
 * @param {function} done - Optional callback to fire when app has started listening.
 */
async function serveDistributionApi(stackName = defaultLocalStackName, done) {
  const port = process.env.PORT || 5002;
  const requiredEnvVars = [
    'DISTRIBUTION_REDIRECT_ENDPOINT',
    'DISTRIBUTION_ENDPOINT'
  ];

  // Set env variable to mark this as a local run of the API
  process.env.CUMULUS_ENV = 'local';

  // Point distribution API to local
  process.env.DISTRIBUTION_REDIRECT_ENDPOINT = `http://localhost:${port}/redirect`;
  process.env.DISTRIBUTION_ENDPOINT = `http://localhost:${port}`;

  if (inTestMode()) {
    // set env variables
    setAuthEnvVariables();
    process.env.system_bucket = 'localbucket';

    checkEnvVariablesAreSet(requiredEnvVars);

    // create tables if not already created
    await checkOrCreateTables(stackName);

    await prepareServices(stackName, process.env.system_bucket);
    await populateBucket(process.env.system_bucket, stackName);
    await createDBRecords(stackName);
  } else {
    checkEnvVariablesAreSet(requiredEnvVars);
    setTableEnvVariables(stackName);
  }

  console.log(`Starting server on port ${port}`);
  const { distributionApp } = require('../app/distribution'); // eslint-disable-line global-require
  return distributionApp.listen(port, done);
}

/**
 * Removes all additional data from tables and repopulates with original data.
 *
 * @param {string} user - defaults to local user, testUser
 * @param {string} stackName - defaults to local stack, localrun
 * @param {string} systemBucket - defaults to 'localbucket', localrun
 * @param {bool} runIt - Override check to prevent accidental AWS run.  default: 'false'.
 */
async function resetTables(
  user = 'testUser',
  stackName = defaultLocalStackName,
  systemBucket = 'localbucket',
  runIt = false
) {
  if (inTestMode() || runIt) {
    setTableEnvVariables(stackName);
    process.env.system_bucket = systemBucket;
    process.env.stackName = stackName;

    // Remove all data from tables
    const providerModel = new models.Provider();
    const collectionModel = new models.Collection();
    const rulesModel = new models.Rule();
    const executionModel = new models.Execution();
    const granulesModel = new models.Granule();
    const pdrsModel = new models.Pdr();

    try {
      await rulesModel.deleteRules();
      await Promise.all([
        collectionModel.deleteCollections(),
        providerModel.deleteProviders(),
        executionModel.deleteExecutions(),
        granulesModel.deleteGranules(),
        pdrsModel.deletePdrs()
      ]);
    } catch (error) {
      console.log(error);
    }

    // Populate tables with original test data (localstack)
    if (inTestMode()) {
      await createDBRecords(stackName, user);
    }
  }
}

module.exports = {
  serveApi,
  serveDistributionApi,
  resetTables
};
