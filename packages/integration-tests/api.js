'use strict';

const cloneDeep = require('lodash.clonedeep');
const {
  aws: { lambda }
} = require('@cumulus/common');
const {
  models: { User },
  testUtils: { createFakeUser }
} = require('@cumulus/api');

/**
 * Call the Cumulus API by invoking the Lambda function that backs the API
 * Gateway endpoint.
 *
 * Intended for use with integration tests.  Will invoke the function in AWS
 * Lambda.  This function will handle authorization of the request.
 *
 * @param {Object} params - params
 * @param {string} params.prefix - the prefix configured for the stack
 * @param {string} params.functionName - the name of the Lambda function that
 *   backs the API Gateway endpoint.  Does not include the stack prefix in the
 *   name.
 * @param {string} params.payload - the payload to send to the Lambda function.
 *   See https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
 * @returns {Promise<Object>} - the parsed payload of the response.  See
 *   https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-output-format
 */
async function callCumulusApi({ prefix, functionName, payload: userPayload }) {
  const payload = cloneDeep(userPayload);

  const userDbClient = new User(`${prefix}-UsersTable`);

  const { userName, password } = await createFakeUser({ userDbClient });

  // Add authorization header to the request
  payload.headers = payload.headers || {};
  payload.headers.Authorization = `Bearer ${password}`;

  let apiOutput;
  try {
    apiOutput = await lambda().invoke({
      Payload: JSON.stringify(payload),
      FunctionName: `${prefix}-${functionName}`
    }).promise();
  }
  finally {
    // Delete the user created for this request
    await userDbClient.delete({ userName });
  }

  return JSON.parse(apiOutput.Payload);
}

/**
 * Fetch a granule from the Cumulus API
 *
 * @param {Object} params - params
 * @param {string} params.prefix - the prefix configured for the stack
 * @param {string} params.granuleId - a granule ID
 * @returns {Promise<Object>} - the granule fetched by the API
 */
async function getGranule({ prefix, granuleId }) {
  const payload = await callCumulusApi({
    prefix: prefix,
    functionName: 'ApiGranulesDefault',
    payload: {
      httpMethod: 'GET',
      resource: '/granules/{granuleName}',
      path: `/granules/${granuleId}`,
      pathParameters: {
        granuleName: granuleId
      }
    }
  });

  return JSON.parse(payload.body);
}

/**
 * Reingest a granule from the Cumulus API
 *
 * @param {Object} params - params
 * @param {string} params.prefix - the prefix configured for the stack
 * @param {string} params.granuleId - a granule ID
 * @returns {Promise<Object>} - the granule fetched by the API
 */
async function reingestGranule({ prefix, granuleId }) {
  const payload = await callCumulusApi({
    prefix: prefix,
    functionName: 'ApiGranulesDefault',
    payload: {
      httpMethod: 'PUT',
      resource: '/v1/granules/{granuleName}',
      path: `/v1/granules/${granuleId}`,
      pathParameters: {
        granuleName: granuleId
      },
      body: JSON.stringify({ action: 'reingest' })
    }
  });

  return JSON.parse(payload.body);
}

/**
 * Removes a granule from CMR via the Cumulus API
 *
 * @param {Object} params - params
 * @param {string} params.prefix - the prefix configured for the stack
 * @param {string} params.granuleId - a granule ID
 * @returns {Promise<Object>} - the granule fetched by the API
 */
async function removeFromCMR({ prefix, granuleId }) {
  const payload = await callCumulusApi({
    prefix: prefix,
    functionName: 'ApiGranulesDefault',
    payload: {
      httpMethod: 'PUT',
      resource: '/v1/granules/{granuleName}',
      path: `/v1/granules/${granuleId}`,
      pathParameters: {
        granuleName: granuleId
      },
      body: JSON.stringify({ action: 'removeFromCmr' })
    }
  });

  return JSON.parse(payload.body);
}

module.exports = {
  callCumulusApi,
  getGranule,
  reingestGranule,
  removeFromCMR
};
