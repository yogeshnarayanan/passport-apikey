/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , BadRequestError = require('./errors/badrequesterror');


/**
 * `Strategy` constructor.
 *
 * The local api key authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `apiKeyField`  field name where the apiKey is found, defaults to _apiKey_
 *   - `apiSecretField`  field name where the apiSecret is found, defaults to _apiSecret_
 *   - `apiKeyHeader`  header name where the apiKey is found, defaults to _apiKey_
 *   - `apiSecretHeader`  header name where the apiSecret is found, defaults to _apiSecret_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new APIKeyStrategy(
 *       function(apikey, done) {
 *         User.findOne({ apikey: apikey }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('local authentication strategy requires a verify function');

  this._apiKeyField = options.apiKeyField || 'apiKey';
  this._apiKeyHeader = options.apiKeyHeader || 'apiKey';

  this._apiSecretField = options.apiSecretField || 'apiSecret';
  this._apiSecretHeader = options.apiSecretHeader || 'apiSecret';

  passport.Strategy.call(this);
  this.name = 'apikey';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var apiKey = lookup(req.body, this._apiKeyField)
    || lookup(req.query, this._apiKeyField)
    || lookup(req.headers, this._apiKeyHeader);

  if (!apiKey) {
    return this.fail(new BadRequestError(options.badRequestMessage || 'Missing API Key'));
  }

  var apiSecret = lookup(req.body, this._apiSecretField)
    || lookup(req.query, this._apiSecretField)
    || lookup(req.headers, this._apiSecretHeader);

  if (!apiSecret) {
    return this.fail(new BadRequestError(options.badRequestMessage || 'Missing API Secret'));
  }

  var self = this;

  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }

  if (self._passReqToCallback) {
    this._verify(req, {apiKey, apiSecret}, verified);
  } else {
    this._verify({apiKey, apiSecret}, verified);
  }

  function lookup(obj, field) {
    if (!obj) { return null; }
    var chain = field.split(']').join('').split('[');
    for (var i = 0, len = chain.length; i < len; i++) {
      var prop = obj[chain[i]];
      if (typeof(prop) === 'undefined') { return null; }
      if (typeof(prop) !== 'object') { return prop; }
      obj = prop;
    }
    return null;
  }
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
