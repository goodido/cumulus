'use strict';

const test = require('ava');
const drop = require('lodash.drop');
const clone = require('lodash.clonedeep');
const omit = require('lodash.omit');
const { parseS3Uri } = require('@cumulus/aws-client/S3');
const { randomString } = require('@cumulus/common/test-utils');
const { RecordDoesNotExist } = require('@cumulus/common/errors');

const models = require('../../models');
const { fakeGranuleFactory, fakeFileFactory } = require('../../lib/testUtils');

process.env.stackName = randomString();
process.env.FilesTable = randomString();
process.env.GranulesTable = randomString();
const fileModel = new models.FileClass();
const granuleModel = new models.Granule();

test.before(async () => {
  await fileModel.createTable();
  await granuleModel.createTable();
});

test.after.always(async () => {
  await fileModel.deleteTable();
  await granuleModel.deleteTable();
});

test.serial('create files records from a granule and then delete them', async (t) => {
  const bucket = randomString();
  const granule = fakeGranuleFactory();
  granule.files = [];
  for (let i = 0; i < 27; i += 1) {
    granule.files.push(fakeFileFactory({ bucket }));
  }

  await fileModel.createFilesFromGranule(granule);

  // make sure all the records are added
  await Promise.all(granule.files.map(async (file) => {
    const record = await fileModel.get({ bucket, key: file.key });
    t.is(record.bucket, file.bucket);
    t.is(record.key, file.key);
    t.is(record.granuleId, granule.granuleId);
  }));

  await fileModel.deleteFilesOfGranule(granule);

  const validateFile = async (file) => {
    try {
      await fileModel.get({ bucket, key: file.key });
      t.fail('Expected an exception to be thrown');
    } catch (err) {
      t.true(err instanceof RecordDoesNotExist);
      // t.true(err.message.includes('No record'));
    }
  };

  await Promise.all(granule.files.map(validateFile));
});

test.serial('create a granule wth 4 files, then remove one of the files', async (t) => {
  const bucket = randomString();
  const granule = fakeGranuleFactory();
  granule.files = [];
  for (let i = 0; i < 4; i += 1) {
    granule.files.push(fakeFileFactory({ bucket }));
  }

  await fileModel.createFilesFromGranule(granule);

  const newGranule = clone(granule);
  const droppedFile = granule.files[0];
  newGranule.files = drop(granule.files);

  await fileModel.deleteFilesAfterCompare(newGranule, granule);

  const validateFile = async (file) => {
    const record = await fileModel.get({ bucket, key: file.key });
    t.is(record.bucket, file.bucket);
    t.is(record.key, file.key);
    t.is(record.granuleId, granule.granuleId);
  };

  // make sure all the records are added
  await Promise.all(newGranule.files.map(validateFile));

  await t.throwsAsync(
    () => fileModel.get({ bucket: bucket, key: droppedFile.key }),
    { instanceOf: RecordDoesNotExist }
  );
});

test.serial('create a granule wth 4 files with just a source, then remove one of the files', async (t) => {
  const bucket = randomString();
  const granule = fakeGranuleFactory();
  granule.files = [];
  for (let i = 0; i < 4; i += 1) {
    granule.files.push({ source: `s3://${bucket}/${randomString()}` });
  }

  await fileModel.createFilesFromGranule(granule);

  const newGranule = clone(granule);
  const droppedFile = parseS3Uri(granule.files[0].source);
  newGranule.files = drop(granule.files);

  await fileModel.deleteFilesAfterCompare(newGranule, granule);

  const validateFile = async (file) => {
    const { Key } = parseS3Uri(file.source);
    const record = await fileModel.get({ bucket, key: Key });
    t.is(record.bucket, bucket);
    t.is(record.key, Key);
    t.is(record.granuleId, granule.granuleId);
  };

  // make sure all the records are added
  await Promise.all(newGranule.files.map(validateFile));

  await t.throwsAsync(
    () => fileModel.get({ bucket: bucket, key: droppedFile.Key }),
    { instanceOf: RecordDoesNotExist }
  );
});

test('getBucketAndKey returns correct bucket and key when file has a bucket and key', (t) => {
  const file = {
    bucket: 'fake-bucket',
    key: 'fake-key',
    source: 's3://fake-source-bucket/key' // keeping this different from bucket/key intentionally
  };

  t.deepEqual(fileModel.getBucketAndKey(file), { bucket: 'fake-bucket', key: 'fake-key' });
});

test('getBucketAndKey returns correct bucket and key when file does not have a bucket and key', (t) => {
  const file = {
    source: 's3://fake-source-bucket/fake-key'
  };

  t.deepEqual(fileModel.getBucketAndKey(file), { bucket: 'fake-source-bucket', key: 'fake-key' });
});

test.serial('getGranuleForFile returns granule of the file', async (t) => {
  const bucket = randomString();
  const granule = fakeGranuleFactory();
  granule.files = [];
  for (let i = 0; i < 4; i += 1) {
    granule.files.push(fakeFileFactory({ bucket }));
  }

  await granuleModel.create(granule);
  await fileModel.createFilesFromGranule(granule);

  // granule can be retrieved for each file
  const validateCollIds = async (file) => {
    const associatedGranule = await fileModel.getGranuleForFile(file.bucket, file.key);
    t.deepEqual(omit(associatedGranule, ['updatedAt']), omit(granule, ['updatedAt']));
  };

  await Promise.all(granule.files.map(validateCollIds));

  // return null if the file doesn't exist
  const associatedGran = await fileModel.getGranuleForFile(randomString(), randomString());
  t.falsy(associatedGran);

  // return null if the granule doesn't exist
  await granuleModel.delete({ granuleId: granule.granuleId });
  const validates = async (file) => {
    const associatedGranule = await fileModel.getGranuleForFile(file.bucket, file.key);
    t.falsy(associatedGranule);
  };

  await Promise.all(granule.files.map(validates));
});
