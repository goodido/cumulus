'use strict';

const fs = require('fs-extra');
const os = require('os');
const path = require('path');
const test = require('ava');
const { Readable } = require('stream');
const { generateChecksumFromStream } = require('@cumulus/checksum');
const {
  calculateS3ObjectChecksum,
  fileExists,
  kms,
  recursivelyDeleteS3Bucket,
  s3,
  s3PutFile,
  s3PutObject,
  headObject
} = require('../aws');

const KMS = require('../aws-client-KMS');
const { S3KeyPairProvider } = require('../key-pair-provider');
const { randomString } = require('../test-utils');
const { Sftp } = require('../sftp');

const encryptedPrivateKey = 'encrypted_ssh_client_rsa_key';
const privateKey = 'ssh_client_rsa_key';

const sftpConfig = {
  host: '127.0.0.1',
  port: '2222',
  username: 'user',
  encrypted: false,
  privateKey
};

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

  const privateKeyPath = path.join('..', 'test-data', 'keys', privateKey);

  // Upload the unencrypted SFTP private key to S3
  await s3PutFile(
    process.env.system_bucket,
    `${process.env.stackName}/crypto/${privateKey}`,
    privateKeyPath
  );

  // Upload the encrypted SFTP private key to S3
  await s3PutObject({
    Bucket: process.env.system_bucket,
    Key: `${process.env.stackName}/crypto/${encryptedPrivateKey}`,
    Body: await KMS.encrypt(
      process.env.providersKeyId,
      await fs.readFile(privateKeyPath, 'utf8')
    )
  });
});

test.after.always(() => recursivelyDeleteS3Bucket(process.env.system_bucket));

test('connect() succeeds with an unencrypted username and password', async (t) => {
  const testSftpClient = new Sftp({
    host: '127.0.0.1',
    port: '2222',
    encrypted: false,
    username: 'user',
    password: 'password'
  });

  await testSftpClient.connect();

  const list = await testSftpClient.list('/');
  t.is(list.length > 0, true);

  await testSftpClient.end();
});

test('connect() succeeds with an S3KeyPairProvider-encrypted username and password', async (t) => {
  const testSftpClient = new Sftp({
    host: '127.0.0.1',
    port: '2222',
    encrypted: true,
    username: await S3KeyPairProvider.encrypt('user'),
    password: await S3KeyPairProvider.encrypt('password')
  });

  await testSftpClient.connect();

  const list = await testSftpClient.list('/');
  t.is(list.length > 0, true);

  await testSftpClient.end();
});

test('connect() succeeds with an KMS-encrypted username and password', async (t) => {
  const testSftpClient = new Sftp({
    host: '127.0.0.1',
    port: '2222',
    encrypted: true,
    username: await KMS.encrypt(process.env.providersKeyId, 'user'),
    password: await KMS.encrypt(process.env.providersKeyId, 'password')
  });

  await testSftpClient.connect();

  const list = await testSftpClient.list('/');
  t.is(list.length > 0, true);

  await testSftpClient.end();
});

test('connect() succeeds with an unencrypted private key', async (t) => {
  const testSftpClient = new Sftp({
    host: '127.0.0.1',
    port: '2222',
    encrypted: true,
    username: await KMS.encrypt(process.env.providersKeyId, 'user'),
    cmKeyId: undefined,
    privateKey
  });

  await testSftpClient.connect();

  const list = await testSftpClient.list('/');
  t.is(list.length > 0, true);

  await testSftpClient.end();
});

test.only('connect() succeeds with an encrypted private key', async (t) => {
  const testSftpClient = new Sftp({
    host: '127.0.0.1',
    port: '2222',
    encrypted: true,
    username: await KMS.encrypt(process.env.providersKeyId, 'user'),
    cmKeyId: process.env.providersKeyId,
    privateKey: encryptedPrivateKey
  });

  await testSftpClient.connect();

  const list = await testSftpClient.list('/');
  t.is(list.length > 0, true);

  await testSftpClient.end();
});

test('connect and retrieve list of files', async (t) => {
  const testSftpClient = new Sftp(sftpConfig);
  await testSftpClient.connect();
  const list = await testSftpClient.list('/');
  t.is(list.length > 0, true);
  await testSftpClient.end();
});

test('Download remote file to local disk', async (t) => {
  const testSftpClient = new Sftp(sftpConfig);

  const localPath = path.join(os.tmpdir(), `delete-me-${randomString()}.txt`);
  await testSftpClient.download(
    '/granules/MOD09GQ.A2017224.h27v08.006.2017227165029.hdf', localPath
  );

  const sum = await generateChecksumFromStream('CKSUM', fs.createReadStream(localPath));
  t.is(sum, 1435712144);
  fs.unlinkSync(localPath);
  await testSftpClient.end();
});

test('Transfer remote file to s3 with correct content-type', async (t) => {
  const testSftpClient = new Sftp(sftpConfig);
  const expectedContentType = 'application/x-hdf';

  const key = `${randomString()}.hdf`;
  await testSftpClient.syncToS3(
    '/granules/MOD09GQ.A2017224.h27v08.006.2017227165029.hdf', process.env.system_bucket, key
  );
  t.truthy(fileExists(process.env.system_bucket, key));
  const sum = await calculateS3ObjectChecksum({ algorithm: 'CKSUM', bucket: process.env.system_bucket, key });
  t.is(sum, 1435712144);

  const s3HeadResponse = await headObject(process.env.system_bucket, key);
  t.is(expectedContentType, s3HeadResponse.ContentType);
  await testSftpClient.end();
});

test('Upload file from s3 to remote', async (t) => {
  const s3object = { Bucket: process.env.system_bucket, Key: 'delete-me-test-sftp-uploads3.txt' };
  await s3PutObject({ Body: randomString(), ...s3object });
  const testSftpClient = new Sftp(sftpConfig);
  await testSftpClient.syncFromS3(s3object, `/granules/${s3object.Key}`);
  const s3sum = await calculateS3ObjectChecksum({ algorithm: 'CKSUM', bucket: process.env.system_bucket, key: s3object.Key });
  const filesum = await generateChecksumFromStream('CKSUM', fs.createReadStream(`../test-data/granules/${s3object.Key}`));
  t.is(s3sum, filesum);
  await testSftpClient.end();
  fs.unlinkSync(`../test-data/granules/${s3object.Key}`);
});

test('Upload data string to remote', async (t) => {
  const testSftpClient = new Sftp(sftpConfig);
  const data = `${randomString()}${randomString()}`;
  const fileName = 'delete-me-test-sftp-uploaddata.txt';
  await testSftpClient.uploadFromString(data, `/granules/${fileName}`);

  const dataStream = new Readable();
  dataStream.push(data);
  dataStream.push(null);
  const expectedSum = await generateChecksumFromStream('CKSUM', dataStream);
  const filesum = await generateChecksumFromStream('CKSUM', fs.createReadStream(`../test-data/granules/${fileName}`));
  t.is(expectedSum, filesum);
  await testSftpClient.end();
  fs.unlinkSync(`../test-data/granules/${fileName}`);
});
