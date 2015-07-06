
var path = require('path');
var events = require('events');
var util = require('util');
var express = require('express');
var uuid = require('shortid');
var pwd = require('couch-pwd');
var ms = require('ms');
var moment = require('moment');
var Mail = require('lockit-sendmail');


/**
 * Internal helper functions
 */
function join(view) {
  return path.join(__dirname, 'views', view);
}

function base64_to_base10(str)
{
	var order = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-";
	var base = order.length;
	var num = 0, r;
	while (str.length)
	{
		r = order.indexOf(str.charAt(0));
		str = str.substr(1);
		num *= base;
		num += r;
	}
	return num;
}
	
function base10_to_base64(num)
{
	var order = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-";
	var base = order.length;
	var str = "", r;
	while (num)
	{
		r = num % base;
		num -= r;
		num /= base;
		str = order.charAt(r) + str;
	}
	return str;
}

/**
 * ForgotPassword constructor function.
 *
 * @param {Object} config
 * @param {Object} adapter
 */
var ForgotPassword = module.exports = function(config, adapter) {

  if (!(this instanceof ForgotPassword)) return new ForgotPassword(config, adapter);

  // call super constructor function
  events.EventEmitter.call(this);

  this.config = config;
  this.adapter = adapter;

  // set default route
  var route = config.forgotPassword.route || '/forgot-password';

  // add prefix when rest is active
  if (config.rest) route = '/rest' + route;

  /**
   * Routes
   */

  var router = express.Router();
  router.get(route, this.getForgot.bind(this));
  router.post(route, this.postForgot.bind(this));
  router.get(route + '/:token', this.getToken.bind(this));
  router.post(route + '/:token', this.postToken.bind(this));
  this.router = router;

};

util.inherits(ForgotPassword, events.EventEmitter);



/**
 * GET /forgot-password
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.getForgot = function(req, res, next) {
  var config = this.config;

  // do not handle the route when REST is active
  if (config.rest) return next();

  // custom or built-in view
  var view = config.forgotPassword.views.forgotPassword || join('get-forgot-password');

  res.render(view, {
    title: 'Forgot password',
    basedir: req.app.get('views')
  });
};



/**
 * POST /forgot-password
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.postForgot = function(req, res, next) {
  var config = this.config;
  var adapter = this.adapter;
  var that = this;

  var email = req.body.email;

  var error = null;
  // regexp from https://github.com/angular/angular.js/blob/master/src/ng/directive/input.js#L4
  var EMAIL_REGEXP = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$/;

  // check for valid input
  if (!email || !email.match(EMAIL_REGEXP)) {
    error = 'Email is invalid';

    // send only JSON when REST is active
    if (config.rest) return res.json(403, {error: error});

    // custom or built-in view
    var errorView = config.forgotPassword.views.forgotPassword || join('get-forgot-password');

    res.status(403);
    res.render(errorView, {
      title: 'Forgot password',
      error: error,
      basedir: req.app.get('views')
    });
    return;
  }

  // looks like given email address has the correct format

  // look for user in db
  adapter.find('email', email, function(err, user) {
    if (err) return next(err);
	if (user) {
		if(user.accountInvalid) {
		  error = 'That account email is invalid';
		  // send only JSON when REST is active
		  if (config.rest) return res.json(403, {error: error});
		  
		  var errorView = config.forgotPassword.views.forgotPassword || join('get-forgot-password');

		  // render template with error message
		  res.status(403);
		  res.render(errorView, {
			title: 'Forgot password',
			error: error,
			basedir: req.app.get('views'),
			email: email
		  });
		  return;
		}
	}
    // custom or built-in view
    var view = config.forgotPassword.views.sentEmail || join('post-forgot-password');

    // no user found -> pretend we sent an email
    if (!user) {
      // send only JSON when REST is active
      if (config.rest) return res.send(204);

      res.render(view, {
        title: 'Forgot password',
        basedir: req.app.get('views')
      });
      return;
    }

    // user found in db
    // do not delete old password as it might be someone else
    // send link with setting new password page
    var token = base64_to_base10(uuid.generate()).toString();
    user.pwdResetToken = token;

    // set expiration date for password reset token
    var timespan = ms(config.forgotPassword.tokenExpiration);
    user.pwdResetTokenExpires = moment().add(timespan, 'ms').toDate();

    // update user in db
    adapter.update(user, function(err, user) {
      if (err) return next(err);

      // send email with forgot password link
      var mail = new Mail(config);
      mail.forgot(user.name, user.email, token, function(err, response) {
        if (err) return next(err);

        // emit event
        that.emit('forgot::sent', user, res);

        // send only JSON when REST is active
        if (config.rest) return res.send(204);

        res.render(view, {
          title: 'Forgot password',
          basedir: req.app.get('views')
        });
      });

    });

  });
};



/**
 * GET /forgot-password/:token
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.getToken = function(req, res, next) {
  var config = this.config;
  var adapter = this.adapter;

  // get token from url
  var token = req.params.token;

  // if format is wrong no need to query the database
  if (!uuid.isValid(base10_to_base64(token))) return next();

  // check if we have a user with that token
  adapter.find('pwdResetToken', token, function(err, user) {
    if (err) return next(err);

    // if no user is found forward to error handling middleware
    if (!user) return next();

    // check if token has expired
    if (new Date(user.pwdResetTokenExpires) < new Date()) {
      // make old token invalid
      delete user.pwdResetToken;
      delete user.pwdResetTokenExpires;

      // update user in db
      adapter.update(user, function(err, user) {
        if (err) return next(err);

        // send only JSON when REST is active
        if (config.rest) return res.json(403, {error: 'link expired'});

        // custom or built-in view
        var view = config.forgotPassword.views.linkExpired || join('link-expired');

        // tell user that link has expired
        res.render(view, {
          title: 'Forgot password - Link expired',
          basedir: req.app.get('views')
        });

      });

      return;
    }

    // send only JSON when REST is active
    if (config.rest) return res.send(204);

    // custom or built-in view
    var view = config.forgotPassword.views.newPassword || join('get-new-password');

    // render success message
    res.render(view, {
      token: token,
      title: 'Choose a new password',
      basedir: req.app.get('views')
    });

  });
};



/**
 * POST /forgot-password/:token
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.postToken = function(req, res, next) {
  var config = this.config;
  var adapter = this.adapter;
  var that = this;

  var password = req.body.password;
  var token = req.params.token;

  var error = '';

  // if format is wrong no need to query the database
  if (!uuid.isValid(base10_to_base64(token))) return next();

  // check for valid input
  if (!password) {
    error = 'Please enter a password';

    // send only JSON when REST is active
    if (config.rest) return res.json(403, {error: error});

    // custom or built-in view
    var view = config.forgotPassword.views.forgotPassword || join('get-forgot-password');

    res.status(403);
    res.render(view, {
      title: 'Choose a new password',
      error: error,
      token: token,
      basedir: req.app.get('views')
    });
    return;
  }

  // check for token in db
  adapter.find('pwdResetToken', token, function(err, user) {
    if (err) return next(err);

    // if no token is found forward to error handling middleware
    if (!user) return next();

    // check if token has expired
    if (new Date(user.pwdResetTokenExpires) < new Date()) {
      // make old token invalid
      delete user.pwdResetToken;
      delete user.pwdResetTokenExpires;

      // update user in db
      adapter.update(user, function(err, user) {
        if (err) return next(err);

        // send only JSON when REST is active
        if (config.rest) return res.json(403, {error: 'link expired'});

        // custom or built-in view
        var view = config.forgotPassword.views.linkExpired || join('link-expired');

        // tell user that link has expired
        res.render(view, {
          title: 'Forgot password - Link expired',
          basedir: req.app.get('views')
        });

      });

      return;
    }

    // if user comes from couchdb it has an 'iterations' key
    if (user.iterations) pwd.iterations(user.iterations);

    // create hash for new password
    pwd.hash(password, function(err, salt, hash) {
      if (err) return next(err);

      // update user's credentials
      user.salt = salt;
      user.derived_key = hash;

      // remove helper properties
      delete user.pwdResetToken;
      delete user.pwdResetTokenExpires;

      // update user in db
      adapter.update(user, function(err, user) {
        if (err) return next(err);

        // emit event
        that.emit('forgot::success', user, res);

        // send only JSON when REST is active
        if (config.rest) return res.send(204);

        // custom or built-in view
        var view = config.forgotPassword.views.changedPassword || join('change-password-success');

        // render success message
        res.render(view, {
          title: 'Password changed',
          basedir: req.app.get('views')
        });

      });

    });
  });
};
