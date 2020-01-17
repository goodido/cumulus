'use strict';

const sinon = require('sinon');
const path = require('path');
const proxyquire = require('proxyquire');
const test = require('ava');
const JSFtp = require('jsftp');
const KMS = require('@cumulus/common/aws-client-KMS');
const {
  calculateS3ObjectChecksum,
  fileExists,
  kms,
  recursivelyDeleteS3Bucket,
  s3,
  s3PutFile,
  headObject
} = require('@cumulus/common/aws');
const { S3KeyPairProvider } = require('@cumulus/common/key-pair-provider');
const { randomString } = require('@cumulus/common/test-utils');
const FtpProviderClient = require('../FtpProviderClient');

test.before(async () => {
  const createKeyResponse = await kms().createKey({}).promise();
  process.env.providersKeyId = createKeyResponse.KeyMetadata.KeyId;

  process.env.stackName = randomString();

  process.env.system_bucket = randomString();
  await s3().createBucket({ Bucket: process.env.system_bucket }).promise();

  // Upload the S3KeyPairProvider public key to S3
  await s3PutFile(
    process.env.system_bucket,
    `${process.env.stackName}/crypto/public.pub`,
    path.join(__dirname, 'fixtures', 'public.pub')
  );

  // Upload the S3KeyPairProvider private key to S3
  await s3PutFile(
    process.env.system_bucket,
    `${process.env.stackName}/crypto/private.pem`,
    path.join(__dirname, 'fixtures', 'private.pem')
  );
});

test.after.always(() => recursivelyDeleteS3Bucket(process.env.system_bucket));

test('useList is present and true when assigned', async (t) => {
  const jsftpSpy = sinon.spy(JSFtp);
  const ProxiedFtpProviderClient = proxyquire('../FtpProviderClient', {
    jsftp: jsftpSpy
  });

  const myFtpProviderClient = new ProxiedFtpProviderClient({
    host: '127.0.0.1',
    username: 'testuser',
    password: 'testpass',
    path: '',
    useList: true
  });

  await myFtpProviderClient.list();

  t.is(jsftpSpy.callCount, 1);
  t.is(jsftpSpy.getCall(0).args[0].useList, true);
});

test('useList defaults to false when not assigned', async (t) => {
  const jsftpSpy = sinon.spy(JSFtp);
  const ProxiedFtpProviderClient = proxyquire('../FtpProviderClient', {
    jsftp: jsftpSpy
  });

  const myFtpProviderClient = new ProxiedFtpProviderClient({
    host: '127.0.0.1',
    username: 'testuser',
    password: 'testpass',
    path: ''
  });

  await myFtpProviderClient.list();

  t.is(jsftpSpy.callCount, 1);
  t.is(jsftpSpy.getCall(0).args[0].useList, false);
});

test('Download remote file to s3 with correct content-type', async (t) => {
  const myFtpProviderClient = new FtpProviderClient({
    host: '127.0.0.1',
    username: 'testuser',
    password: 'testpass',
    path: '',
    useList: true
  });

  const bucket = randomString();
  const key = `${randomString()}.hdf`;
  const expectedContentType = 'application/x-hdf';
  try {
    await s3().createBucket({ Bucket: bucket }).promise();
    await myFtpProviderClient.sync(
      '/granules/MOD09GQ.A2017224.h27v08.006.2017227165029.hdf', bucket, key
    );
    t.truthy(fileExists(bucket, key));
    const sum = await calculateS3ObjectChecksum({ algorithm: 'CKSUM', bucket, key });
    t.is(sum, 1435712144);

    const s3HeadResponse = await headObject(bucket, key);
    t.is(expectedContentType, s3HeadResponse.ContentType);
  } finally {
    await recursivelyDeleteS3Bucket(bucket);
  }
});

test('connect() succeeds with an unencrypted username and password', async (t) => {
  const myFtpProviderClient = new FtpProviderClient({
    host: '127.0.0.1',
    encrypted: false,
    username: 'testuser',
    password: 'testpass',
    path: ''
  });

  const files = await myFtpProviderClient.list();

  t.true(files.length > 0);
});

test('connect() succeeds with an S3KeyPairProvider-encrypted username and password', async (t) => {
  const myFtpProviderClient = new FtpProviderClient({
    host: '127.0.0.1',
    encrypted: true,
    username: await S3KeyPairProvider.encrypt('testuser'),
    password: await S3KeyPairProvider.encrypt('testpass'),
    path: ''
  });

  const files = await myFtpProviderClient.list();

  t.true(files.length > 0);
});

test('connect() succeeds with an KMS-encrypted username and password', async (t) => {
  const myFtpProviderClient = new FtpProviderClient({
    host: '127.0.0.1',
    encrypted: true,
    username: await KMS.encrypt(process.env.providersKeyId, 'testuser'),
    password: await KMS.encrypt(process.env.providersKeyId, 'testpass'),
    path: ''
  });

  const files = await myFtpProviderClient.list();

  t.true(files.length > 0);
});
