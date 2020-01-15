'use strict';

const test = require('ava');
const awsServices = require('@cumulus/aws-client/services');
const { recursivelyDeleteS3Bucket } = require('@cumulus/aws-client/S3');
const request = require('supertest');
const { randomString } = require('@cumulus/common/test-utils');
const {
  createFakeJwtAuthToken,
  setAuthorizedOAuthUsers
} = require('../../lib/testUtils');
const assertions = require('../../lib/assertions');
const models = require('../../models');

process.env.invoke = 'granule-reconciliation-reports';
process.env.stackName = 'test-stack';
process.env.AccessTokensTable = randomString();
process.env.TOKEN_SECRET = randomString();

// import the express app after setting the env variables
const { app } = require('../../app');

const reportNames = [randomString(), randomString()];
const reportDirectory = `${process.env.stackName}/reconciliation-reports`;

let accessTokenModel;

test.before(async () => {
  accessTokenModel = new models.AccessToken();
  await accessTokenModel.createTable();
});

test.beforeEach(async (t) => {
  process.env.system_bucket = 'test_system_bucket';
  await awsServices.s3().createBucket({ Bucket: process.env.system_bucket }).promise();

  const username = randomString();
  await setAuthorizedOAuthUsers([username]);

  t.context.jwtAuthToken = await createFakeJwtAuthToken({ accessTokenModel, username });

  await Promise.all(reportNames.map((reportName) =>
    awsServices.s3().putObject({
      Bucket: process.env.system_bucket,
      Key: `${reportDirectory}/${reportName}`,
      Body: JSON.stringify({ test_key: `${reportName} test data` })
    }).promise()));
});

test.afterEach.always(async () => {
  await recursivelyDeleteS3Bucket(process.env.system_bucket);
});

test.after.always(async () => {
  await accessTokenModel.deleteTable();
});

test.serial('CUMULUS-911 GET without pathParameters and without an Authorization header returns an Authorization Missing response', async (t) => {
  const response = await request(app)
    .get('/reconciliationReports')
    .set('Accept', 'application/json')
    .expect(401);

  assertions.isAuthorizationMissingResponse(t, response);
});

test.serial('CUMULUS-911 GET with pathParameters and without an Authorization header returns an Authorization Missing response', async (t) => {
  const response = await request(app)
    .get('/reconciliationReports/asdf')
    .set('Accept', 'application/json')
    .expect(401);

  assertions.isAuthorizationMissingResponse(t, response);
});

test.serial('CUMULUS-911 POST without an Authorization header returns an Authorization Missing response', async (t) => {
  const response = await request(app)
    .post('/reconciliationReports')
    .set('Accept', 'application/json')
    .expect(401);

  assertions.isAuthorizationMissingResponse(t, response);
});

test.serial('CUMULUS-911 DELETE with pathParameters and without an Authorization header returns an Authorization Missing response', async (t) => {
  const response = await request(app)
    .delete('/reconciliationReports/asdf')
    .set('Accept', 'application/json')
    .expect(401);

  assertions.isAuthorizationMissingResponse(t, response);
});

test.serial('CUMULUS-911 GET without pathParameters and with an invalid access token returns an unauthorized response', async (t) => {
  const response = await request(app)
    .get('/reconciliationReports')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer ThisIsAnInvalidAuthorizationToken')
    .expect(403);

  assertions.isInvalidAccessTokenResponse(t, response);
});

test.todo('CUMULUS-911 GET without pathParameters and with an unauthorized user returns an unauthorized response');

test.serial('CUMULUS-911 GET with pathParameters and with an invalid access token returns an unauthorized response', async (t) => {
  const response = await request(app)
    .get('/reconciliationReports/asdf')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer ThisIsAnInvalidAuthorizationToken')
    .expect(403);

  assertions.isInvalidAccessTokenResponse(t, response);
});

test.todo('CUMULUS-911 GET with pathParameters and with an unauthorized user returns an unauthorized response');

test.serial('CUMULUS-911 POST with an invalid access token returns an unauthorized response', async (t) => {
  const response = await request(app)
    .post('/reconciliationReports')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer ThisIsAnInvalidAuthorizationToken')
    .expect(403);

  assertions.isInvalidAccessTokenResponse(t, response);
});

test.todo('CUMULUS-911 POST with an unauthorized user returns an unauthorized response');

test.serial('CUMULUS-911 DELETE with pathParameters and with an invalid access token returns an unauthorized response', async (t) => {
  const response = await request(app)
    .delete('/reconciliationReports/asdf')
    .set('Accept', 'application/json')
    .set('Authorization', 'Bearer ThisIsAnInvalidAuthorizationToken')
    .expect(403);

  assertions.isInvalidAccessTokenResponse(t, response);
});

test.todo('CUMULUS-911 DELETE with pathParameters and with an unauthorized user returns an unauthorized response');

test.serial('default returns list of reports', async (t) => {
  const { jwtAuthToken } = t.context;

  const response = await request(app)
    .get('/reconciliationReports')
    .set('Accept', 'application/json')
    .set('Authorization', `Bearer ${jwtAuthToken}`)
    .expect(200);

  const results = response.body;
  t.is(results.results.length, 2);
  results.results.forEach((reportName) => t.true(reportNames.includes(reportName)));
});

test.serial('get a report', async (t) => {
  const { jwtAuthToken } = t.context;

  await Promise.all(reportNames.map(async (reportName) => {
    const response = await request(app)
      .get(`/reconciliationReports/${reportName}`)
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${jwtAuthToken}`)
      .expect(200);
    t.deepEqual(response.body, { test_key: `${reportName} test data` });
  }));
});

test.serial('get 404 if the report doesnt exist', async (t) => {
  const { jwtAuthToken } = t.context;

  const response = await request(app)
    .get('/reconciliationReports/404file')
    .set('Accept', 'application/json')
    .set('Authorization', `Bearer ${jwtAuthToken}`)
    .expect(404);
  t.is(response.status, 404);
  t.is(response.body.message, 'The report does not exist!');
});

test.serial('delete a report', async (t) => {
  const { jwtAuthToken } = t.context;

  await Promise.all(reportNames.map(async (reportName) => {
    const response = await request(app)
      .delete(`/reconciliationReports/${reportName}`)
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${jwtAuthToken}`)
      .expect(200);
    t.deepEqual(response.body, { message: 'Report deleted' });
  }));
});

test.serial('create a report', async (t) => {
  const { jwtAuthToken } = t.context;

  const response = await request(app)
    .post('/reconciliationReports')
    .set('Accept', 'application/json')
    .set('Authorization', `Bearer ${jwtAuthToken}`)
    .expect(200);

  const content = response.body;
  t.is(content.message, 'Report is being generated');
});
