/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The pnut.io authentication strategy authenticates requests by delegating to
 * pnut.io using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your pnut.io application's App ID
 *   - `clientSecret`  your pnut.io application's App Secret
 *   - `callbackURL`   URL to which pnut.io will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new PnutStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/pnut/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
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
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://pnut.io/oauth/authenticate';
  options.tokenURL = options.tokenURL || 'https://api.pnut.io/v0/oauth/access_token';
  options.scopeSeparator = options.scopeSeparator || '%20';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'pnut';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Return extra pnut.io-specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `state`  A unique string used to maintain application state between the request and callback. Helpful in preventing XSS attacks. Gets appended to the end of the Callback URL to which pnut.io redirects the user after authentication.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (options) {
  var params = {},
      state = options.state;

  if (state) {
    params['state'] = state;
  }

  return params;
};

/**
 * Retrieve user profile from pnut.io.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `facebook`
 *   - `id`               the user's pnut.io ID
 *   - `username`         the user's pnut.io username
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on pnut.io
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.getProtectedResource('https://api.pnut.io/v0/users/me', accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body).data || JSON.parse(body);

      var profile = { provider: 'pnut' };
      profile.id = json.id;
      profile.username = json.username;
      profile.displayName = json.name;
      profile.gender = json.gender;
      profile.profileUrl = 'https://pnut.io/@' + json.username;

      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;