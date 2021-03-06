'use strict';

const uuidv4 = require('uuid/v4');
const {
  aws: { ecs, s3 },
  testUtils: { randomString }
} = require('@cumulus/common');
const {
  getClusterArn,
  waitForAsyncOperationStatus
} = require('@cumulus/integration-tests');
const { AsyncOperation } = require('@cumulus/api/models');
const { loadConfig } = require('../../helpers/testUtils');

describe('The AsyncOperation task runner', () => {
  let asyncOperationModel;
  let config;
  let cluster;
  let asyncOperationsTableName;
  let asyncOperationTaskDefinition;
  let successFunctionName;
  let failFunctionName;

  beforeAll(async () => {
    config = await loadConfig();

    asyncOperationsTableName = `${config.stackName}-AsyncOperationsTable`;
    successFunctionName = `${config.stackName}-AsyncOperationSuccess`;
    failFunctionName = `${config.stackName}-AsyncOperationFail`;

    asyncOperationModel = new AsyncOperation({
      stackName: config.stackName,
      systemBucket: config.bucket,
      tableName: asyncOperationsTableName
    });

    // Find the ARN of the cluster
    cluster = await getClusterArn(config.stackName);

    // Find the ARN of the AsyncOperationTaskDefinition
    const { taskDefinitionArns } = await ecs().listTaskDefinitions().promise();
    asyncOperationTaskDefinition = taskDefinitionArns.find(
      (arn) => arn.includes(`${config.stackName}-AsyncOperationTaskDefinition`)
    );
  });

  describe('running a non-existent lambda function', () => {
    let asyncOperationId;
    let taskArn;
    let dynamoDbItem;

    beforeAll(async () => {
      // Start the AsyncOperation
      ({
        id: asyncOperationId,
        taskArn
      } = await asyncOperationModel.start({
        asyncOperationTaskDefinition,
        cluster,
        lambdaName: 'does-not-exist',
        description: 'Some description',
        operationType: 'ES Index',
        payload: {}
      }));

      await ecs().waitFor(
        'tasksStopped',
        {
          cluster,
          tasks: [taskArn]
        }
      ).promise();

      dynamoDbItem = await waitForAsyncOperationStatus({
        TableName: asyncOperationsTableName,
        id: asyncOperationId,
        status: 'RUNNER_FAILED'
      });
    });

    it('updates the status field in DynamoDB to "RUNNER_FAILED"', async () => {
      expect(dynamoDbItem.status.S).toEqual('RUNNER_FAILED');
    });

    it('updates the output field in DynamoDB', async () => {
      const parsedOutput = JSON.parse(dynamoDbItem.output.S);

      expect(parsedOutput.message).toContain('Function not found');
    });

    it('updates the updatedAt field in DynamoDB', async () => {
      expect(dynamoDbItem.updatedAt.N).toBeGreaterThan(dynamoDbItem.createdAt.N);
    });
  });

  describe('with a non-existent payload', () => {
    let asyncOperationId;
    let taskArn;
    let dynamoDbItem;
    let payloadUrl;

    beforeAll(async () => {
      asyncOperationId = uuidv4();

      await asyncOperationModel.create({
        id: asyncOperationId,
        taskArn: randomString(),
        description: 'Some description',
        operationType: 'ES Index',
        status: 'RUNNING'
      });

      payloadUrl = `s3://${config.bucket}/${randomString()}`;
      const runTaskResponse = await ecs().runTask({
        cluster,
        taskDefinition: asyncOperationTaskDefinition,
        launchType: 'EC2',
        overrides: {
          containerOverrides: [
            {
              name: 'AsyncOperation',
              environment: [
                { name: 'asyncOperationId', value: asyncOperationId },
                { name: 'asyncOperationsTable', value: asyncOperationsTableName },
                { name: 'lambdaName', value: successFunctionName },
                { name: 'payloadUrl', value: payloadUrl }
              ]
            }
          ]
        }
      }).promise();

      taskArn = runTaskResponse.tasks[0].taskArn;

      await ecs().waitFor(
        'tasksStopped',
        {
          cluster,
          tasks: [taskArn]
        }
      ).promise();

      dynamoDbItem = await waitForAsyncOperationStatus({
        TableName: asyncOperationsTableName,
        id: asyncOperationId,
        status: 'RUNNER_FAILED'
      });
    });

    it('updates the status field in DynamoDB to "RUNNER_FAILED"', async () => {
      expect(dynamoDbItem.status.S).toEqual('RUNNER_FAILED');
    });

    it('updates the output field in DynamoDB', async () => {
      const parsedOutput = JSON.parse(dynamoDbItem.output.S);

      expect(parsedOutput.message).toBe(`Failed to fetch ${payloadUrl}: The specified key does not exist.`);
    });

    it('updates the updatedAt field in DynamoDB', async () => {
      expect(dynamoDbItem.updatedAt.N).toBeGreaterThan(dynamoDbItem.createdAt.N);
    });
  });

  describe('with a non-JSON payload', () => {
    let asyncOperationId;
    let taskArn;
    let dynamoDbItem;
    let payloadKey;

    beforeAll(async () => {
      asyncOperationId = uuidv4();

      // Upload the payload
      payloadKey = `${config.stackName}/integration-tests/payloads/${asyncOperationId}.json`;
      await s3().putObject({
        Bucket: config.bucket,
        Key: payloadKey,
        Body: 'invalid JSON'
      }).promise();

      await asyncOperationModel.create({
        id: asyncOperationId,
        taskArn: randomString(),
        description: 'Some description',
        operationType: 'ES Index',
        status: 'RUNNING'
      });

      const runTaskResponse = await ecs().runTask({
        cluster,
        taskDefinition: asyncOperationTaskDefinition,
        launchType: 'EC2',
        overrides: {
          containerOverrides: [
            {
              name: 'AsyncOperation',
              environment: [
                { name: 'asyncOperationId', value: asyncOperationId },
                { name: 'asyncOperationsTable', value: asyncOperationsTableName },
                { name: 'lambdaName', value: successFunctionName },
                { name: 'payloadUrl', value: `s3://${config.bucket}/${payloadKey}` }
              ]
            }
          ]
        }
      }).promise();

      taskArn = runTaskResponse.tasks[0].taskArn;

      await ecs().waitFor(
        'tasksStopped',
        {
          cluster,
          tasks: [taskArn]
        }
      ).promise();

      dynamoDbItem = await waitForAsyncOperationStatus({
        TableName: asyncOperationsTableName,
        id: asyncOperationId,
        status: 'TASK_FAILED'
      });
    });

    it('updates the status field in DynamoDB to "TASK_FAILED"', async () => {
      expect(dynamoDbItem.status.S).toEqual('TASK_FAILED');
    });

    it('updates the output field in DynamoDB', async () => {
      const parsedOutput = JSON.parse(dynamoDbItem.output.S);

      expect(parsedOutput.message).toContain('Unable to parse payload:');
    });

    it('updates the updatedAt field in DynamoDB', async () => {
      expect(dynamoDbItem.updatedAt.N).toBeGreaterThan(dynamoDbItem.createdAt.N);
    });

    afterAll(() => s3().deleteObject({ Bucket: config.bucket, Key: payloadKey }).promise());
  });

  describe('executing a successful lambda function', () => {
    let asyncOperationId;
    let taskArn;
    let dynamoDbItem;
    let payloadKey;

    beforeAll(async () => {
      asyncOperationId = uuidv4();

      // Upload the payload
      payloadKey = `${config.stackName}/integration-tests/payloads/${asyncOperationId}.json`;
      await s3().putObject({
        Bucket: config.bucket,
        Key: payloadKey,
        Body: JSON.stringify([1, 2, 3])
      }).promise();

      await asyncOperationModel.create({
        id: asyncOperationId,
        taskArn: randomString(),
        description: 'Some description',
        operationType: 'ES Index',
        status: 'RUNNING'
      });

      const runTaskResponse = await ecs().runTask({
        cluster,
        taskDefinition: asyncOperationTaskDefinition,
        launchType: 'EC2',
        overrides: {
          containerOverrides: [
            {
              name: 'AsyncOperation',
              environment: [
                { name: 'asyncOperationId', value: asyncOperationId },
                { name: 'asyncOperationsTable', value: asyncOperationsTableName },
                { name: 'lambdaName', value: successFunctionName },
                { name: 'payloadUrl', value: `s3://${config.bucket}/${payloadKey}` }
              ]
            }
          ]
        }
      }).promise();

      taskArn = runTaskResponse.tasks[0].taskArn;

      await ecs().waitFor(
        'tasksStopped',
        {
          cluster,
          tasks: [taskArn]
        }
      ).promise();

      dynamoDbItem = await waitForAsyncOperationStatus({
        TableName: asyncOperationsTableName,
        id: asyncOperationId,
        status: 'SUCCEEDED'
      });
    });

    it('updates the status field in DynamoDB to "SUCCEEDED"', async () => {
      expect(dynamoDbItem.status.S).toEqual('SUCCEEDED');
    });

    it('updates the output field in DynamoDB', async () => {
      const parsedOutput = JSON.parse(dynamoDbItem.output.S);

      expect(parsedOutput).toEqual([1, 2, 3]);
    });

    it('updates the updatedAt field in DynamoDB', async () => {
      expect(dynamoDbItem.updatedAt.N).toBeGreaterThan(dynamoDbItem.createdAt.N);
    });

    afterAll(() => s3().deleteObject({ Bucket: config.bucket, Key: payloadKey }).promise());
  });

  describe('executing a failing lambda function', () => {
    let asyncOperationId;
    let taskArn;
    let dynamoDbItem;
    let payloadKey;

    beforeAll(async () => {
      asyncOperationId = uuidv4();

      // Upload the payload
      payloadKey = `${config.stackName}/integration-tests/payloads/${asyncOperationId}.json`;
      await s3().putObject({
        Bucket: config.bucket,
        Key: payloadKey,
        Body: JSON.stringify([1, 2, 3])
      }).promise();

      await asyncOperationModel.create({
        id: asyncOperationId,
        taskArn: randomString(),
        description: 'Some description',
        operationType: 'ES Index',
        status: 'RUNNING'
      });

      const runTaskResponse = await ecs().runTask({
        cluster,
        taskDefinition: asyncOperationTaskDefinition,
        launchType: 'EC2',
        overrides: {
          containerOverrides: [
            {
              name: 'AsyncOperation',
              environment: [
                { name: 'asyncOperationId', value: asyncOperationId },
                { name: 'asyncOperationsTable', value: asyncOperationsTableName },
                { name: 'lambdaName', value: failFunctionName },
                { name: 'payloadUrl', value: `s3://${config.bucket}/${payloadKey}` }
              ]
            }
          ]
        }
      }).promise();

      taskArn = runTaskResponse.tasks[0].taskArn;

      await ecs().waitFor(
        'tasksStopped',
        {
          cluster,
          tasks: [taskArn]
        }
      ).promise();

      dynamoDbItem = await waitForAsyncOperationStatus({
        TableName: asyncOperationsTableName,
        id: asyncOperationId,
        status: 'TASK_FAILED'
      });
    });

    it('updates the status field in DynamoDB to "TASK_FAILED"', async () => {
      expect(dynamoDbItem.status.S).toEqual('TASK_FAILED');
    });

    it('updates the output field in DynamoDB', async () => {
      const parsedOutput = JSON.parse(dynamoDbItem.output.S);

      expect(parsedOutput.message).toBe('triggered failure');
    });

    it('updates the updatedAt field in DynamoDB', async () => {
      expect(dynamoDbItem.updatedAt.N).toBeGreaterThan(dynamoDbItem.createdAt.N);
    });

    afterAll(() => s3().deleteObject({ Bucket: config.bucket, Key: payloadKey }).promise());
  });
});
