'use strict';

const _get = require('lodash.get');
const { CMR } = require('@cumulus/cmrjs');
const { S3 } = require('@cumulus/ingest/aws');
const { DefaultProvider } = require('@cumulus/ingest/crypto');
const handle = require('../lib/response').handle;
const Search = require('../es/search').Search;
const { partialRecordUpdate, deleteRecord, reingest } = require('../es/indexer');
const log = require('@cumulus/common/log');
const { moveGranuleFiles } = require('@cumulus/ingest/granule');

async function removeGranuleFromCmr(granuleId, collectionId) {
  log.info(`granules.removeGranuleFromCmr ${granuleId}`);
  const password = await DefaultProvider.decrypt(process.env.cmr_password);
  const cmr = new CMR(
    process.env.cmr_provider,
    process.env.cmr_client_id,
    process.env.cmr_username,
    password
  );

  await cmr.deleteGranule(granuleId, collectionId);

  await partialRecordUpdate(
    null,
    granuleId,
    'granule',
    { published: false, cmrLink: null },
    collectionId
  );
}

async function moveGranule(granuleId, destination) {
  const search = new Search({}, 'granule');
  const response = await search.get(granuleId)
  await moveGranuleFiles(response.files, destination)
}

/**
 * List all granules for a given collection.
 *
 * @param {Object} event - aws lambda event object.
 * @param {callback} cb - aws lambda callback function
 * @returns {Object} list of granules
 */
function list(event, cb) {
  const search = new Search(event, 'granule');
  search.query().then((response) => cb(null, response)).catch((e) => {
    cb(e);
  });
}


/**
 * Update a single granule.
 * Supported Actions: reingest, Remove From CMR.
 *
 * @param {Object} event - aws lambda event object.
 * @returns {Promise} response from the actions
 */
async function put(event) {
  const granuleId = _get(event.pathParameters, 'granuleName');
  let body = _get(event, 'body', '{}');
  body = JSON.parse(body);

  const action = _get(body, 'action');

  if (action) {
    const search = new Search({}, 'granule');
    const response = await search.get(granuleId);
    if (action === 'reingest') {
      await reingest(response);
      return {
        granuleId: response.granuleId,
        action,
        status: 'SUCCESS'
      };
    }
    else if (action === 'removeFromCmr') {
      await removeGranuleFromCmr(response.granuleId, response.collectionId);
      return {
        granuleId: response.granuleId,
        action,
        status: 'SUCCESS'
      };
    }
    else if (action === 'move') {
     const destination = body.destination;

     await moveGranule(granuleId, destination)

     return {
       granuleId: response.granuleId,
       action,
       status: 'SUCCESS'
     }

    throw new Error('Action is not supported. Choices are: \'move\', \'reingest\', and \'removeFromCmr\'');
  }

  throw new Error('Action is missing');
}

async function del(event) {
  const granuleId = _get(event.pathParameters, 'granuleName');
  log.info(`granules.del ${granuleId}`);

  const search = new Search({}, 'granule');
  const record = await search.get(granuleId);

  if (record.detail) {
    throw record;
  }

  if (record.published) {
    throw new Error(
      'You cannot delete a granule that is published to CMR. Remove it from CMR first'
    );
  }

  // remove file from s3
  const key = `${process.env.stackName}/granules_ingested/${granuleId}`;
  await S3.delete(process.env.internal, key);

  await deleteRecord(null, granuleId, 'granule', record.collectionId);

  return { detail: 'Record deleted' };
}

/**
 * Query a single granule.
 *
 * @param {Object} event - aws lambda event object.
 * @param {callback} cb - aws lambda callback function
 * @returns {Object} a single granule object.
 */
function get(event, cb) {
  const granuleId = _get(event.pathParameters, 'granuleName');

  const search = new Search({}, 'granule');
  search.get(granuleId).then((response) => {
    cb(null, response);
  }).catch((e) => {
    cb(e);
  });
}


function handler(event, context) {
  handle(event, context, true, (cb) => {
    if (event.httpMethod === 'GET' && event.pathParameters) {
      get(event, cb);
    }
    else if (event.httpMethod === 'PUT' && event.pathParameters) {
      put(event).then((r) => cb(null, r)).catch((e) => cb(e));
    }
    else if (event.httpMethod === 'DELETE' && event.pathParameters) {
      del(event).then((r) => cb(null, r)).catch((e) => cb(e));
    }
    else {
      list(event, cb);
    }
  });
}

module.exports = handler;
