/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , lookup = require('./utils').lookup;

function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('LocalStrategy requires a verify callback'); }
  
  this._roomnumberField = options.roomnumberField || 'roomnumber';
  this._pinField = options.pinField || 'pin';
  
  passport.Strategy.call(this);
  this.name = 'guest';
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
  var roomnumber = lookup(req.body, this._roomnumberField) || lookup(req.query, this._roomnumberField);
  var pin = lookup(req.body, this._pinField) || lookup(req.query, this._pinField);
  
  if (!roomnumber || !pin) {
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }
  
  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  
  try {
    if (self._passReqToCallback) {
      this._verify(req, roomnumber, pin, verified);
    } else {
      this._verify(roomnumber, pin, verified);
    }
  } catch (ex) {
    return self.error(ex);
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
