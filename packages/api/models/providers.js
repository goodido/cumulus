'use strict';

const isIp = require('is-ip');
const { encrypt } = require('@cumulus/common/aws-client-KMS');
const { isNil, removeNilProperties } = require('@cumulus/common/util');
const { isNonEmptyString, isValidHostname } = require('@cumulus/common/string');

const Manager = require('./base');
const providerSchema = require('./schemas').provider;
const Rule = require('./rules');
const { AssociatedRulesError } = require('../lib/errors');

const buildValidationError = ({ detail }) => {
  const err = new Error('The record has validation errors');
  err.name = 'ValidationError';
  err.detail = detail;

  return err;
};

const validateHost = (host) => {
  if (isNil(host)) return;
  if (isValidHostname(host)) return;
  if (isIp(host)) return;

  throw buildValidationError({
    detail: `${host} is not a valid hostname or IP address`
  });
};

class Provider extends Manager {
  static recordIsValid(item, schema = null) {
    super.recordIsValid(item, schema);

    validateHost(item.host);
  }

  constructor() {
    super({
      tableName: process.env.ProvidersTable,
      tableHash: { name: 'id', type: 'S' },
      schema: providerSchema
    });

    this.removeAdditional = 'all';
  }

  /**
   * Check if a given provider exists
   *
   * @param {string} id - provider id
   * @returns {boolean}
   */
  exists(id) {
    return super.exists({ id });
  }

  async update(key, provider, keysToDelete = []) {
    const encryptedUsername = isNonEmptyString(provider.username)
      ? await encrypt(process.env.providersKeyId, provider.username)
      : null;

    const encryptedPassword = isNonEmptyString(provider.password)
      ? await encrypt(process.env.providersKeyId, provider.password)
      : null;

    return super.update(
      key,
      removeNilProperties({
        ...provider,
        username: encryptedUsername,
        password: encryptedPassword
      }),
      keysToDelete
    );
  }

  async create(provider) {
    const username = isNonEmptyString(provider.username)
      ? await encrypt(process.env.providersKeyId, provider.username)
      : null;

    const password = isNonEmptyString(provider.password)
      ? await encrypt(process.env.providersKeyId, provider.password)
      : null;

    const record = removeNilProperties({
      ...provider,
      username,
      password
    });

    return super.create(record);
  }

  /**
   * Delete a provider
   *
   * @param {string} id - the provider id
   */
  async delete({ id }) {
    const associatedRuleNames = (await this.getAssociatedRules(id))
      .map((rule) => rule.name);

    if (associatedRuleNames.length > 0) {
      throw new AssociatedRulesError(
        'Cannot delete a provider that has associated rules',
        associatedRuleNames
      );
    }

    await super.delete({ id });
  }

  async deleteProviders() {
    const providers = await this.scan();
    return Promise.all(providers.Items.map((p) => this.delete({ id: p.id })));
  }

  /**
   * Get any rules associated with the provider
   *
   * @param {string} id - the provider id
   * @returns {Promise<boolean>}
   */
  async getAssociatedRules(id) {
    const ruleModel = new Rule();

    const scanResult = await ruleModel.scan({
      filter: 'provider = :provider',
      values: { ':provider': id }
    });

    return scanResult.Items;
  }
}

module.exports = Provider;
