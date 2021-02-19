var	path = require('path'),
	events = require('events'),
	util = require('util'),
	express = require('express'),
	uuid = require('shortid'),
	pwd = require('couch-pwd'),
	ms = require('ms'),
	moment = require('moment'),
	Mail = require('lockit-sendmail');

/**
 * ForgotPassword constructor function.
 *
 * @param {Object} config
 * @param {Object} adapter
 */
var ForgotPassword = module.exports = function(cfg, adapter)
{
	if(!(this instanceof ForgotPassword))
	{
		return new ForgotPassword(cfg, adapter);
	}

	this.config = cfg;
	this.adapter = adapter;

	var	config = this.config;

	// call super constructor function
	events.EventEmitter.call(this);

	// set default route
	var route = config.forgotPassword.route || '/forgotpassword';

	// add prefix when rest is active
	if(config.rest) 
	{
		route = '/' + config.rest.route + route;
	}

	uuid.characters();

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
 * Response handler
 *
 * @param {Object} err
 * @param {String} view
 * @param {Object} user
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.sendResponse = function(err, view, user, json, req, res, next)
{
	var	config = this.config;

	this.emit((config.forgotPassword.eventMessage || 'ForgotPassword'), err, view, user, res);
	
	if(config.forgotPassword.handleResponse)
	{
		// do not handle the route when REST is active
		if(config.rest)
		{
			if(err)
			{
				res.status(403).json(err);
			}
			else
			{
				res.json(json);
			}
		}
		else
		{
			// custom or built-in view
			var	resp = {
					title: config.forgotPassword.title || 'Forgot Password',
					basedir: req.app.get('views')
				};
				
			if(err)
			{
				resp.error = err.message;
			}
			
			if(view)
			{
				var	file = path.resolve(path.normalize(resp.basedir + '/' + view));
				res.render(view, Object.assign(resp, json));
			}
			else
			{
				res.status(404).send('<p>No file has been set in the configuration for this view path.</p><p>Please make sure you set a valid file for the "forgotPassword.views" configuration.</p>');
			}
		}
	}
	else
	{
		next(err);
	}
};



/**
 * GET /forgot-password
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.getForgot = function(req, res, next)
{
	var config = this.config;
	this.sendResponse(undefined, config.forgotPassword.views.forgotPassword, undefined, {result:true}, req, res, next);
};



/**
 * POST /forgot-password
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.postForgot = function(req, res, next)
{
	var config = this.config,
		adapter = this.adapter,
		that = this,
		email = req.body.email,
		error = null,
		checkEmail = function(e)
		{
			var emailRegex = /^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i;
			if(emailRegex.exec(e) && emailRegex.exec(e)[0] === e)
			{
				return true;
			}
			return false;
		};

	// check for valid input
	if(!email || !checkEmail(email))
	{
		that.sendResponse({message:'The email is invalid'}, config.forgotPassword.views.forgotPassword, undefined, {result:true}, req, res, next);
	}
	else
	{
		// looks like given email address has the correct format

		// Custom for our app
		var basequery = {};
		if(res.locals && res.locals.basequery)
		{
			basequery = res.locals.basequery;
		}

		// look for user in db
		adapter.find('email', email, function(err, user)
		{
			if(err)
			{
				next(err);
			}
			else if(!user)
			{
				that.sendResponse({message:'That account does not exist'}, config.forgotPassword.views.forgotPassword, user, {result:true}, req, res, next);
			}
			else
			{
				if(user.accountInvalid)
				{
					that.sendResponse({message:'That account is invalid'}, config.forgotPassword.views.forgotPassword, user, {result:true}, req, res, next);
				}
				else if(!user.emailVerified)
				{
					that.sendResponse({message:'This email has not been verified'}, config.forgotPassword.views.forgotPassword, user, {result:true}, req, res, next);
				}
				else
				{
					// no user found -> pretend we sent an email

					// user found in db
					// do not delete old password as it might be someone else
					// send link with setting new password page
					var token = uuid.generate();
					user.pwdResetToken = token;

					// set expiration date for password reset token
					var timespan = ms(config.forgotPassword.tokenExpiration);
					user.pwdResetTokenExpires = moment().add(timespan, 'ms').toDate();

					// update user in db
					adapter.update(user, function(err, user)
						{
							if(err)
							{
								next(err);
							}
							else
							{
								// send email with forgot password link
								var mail = new Mail(config);
								mail.forgot(user.name, user.email, token, function(err, response)
									{
										if(err)
										{
											that.sendResponse(err, config.forgotPassword.views.forgotPassword, user, {result:true}, req, res, next);
										}
										else
										{
											that.sendResponse(undefined, config.forgotPassword.views.sentEmail, user, {result:true}, req, res, next);
										}
									});
							}
						});
				}
			}
		}, basequery);
	}
};



/**
 * GET /forgot-password/:token
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.getToken = function(req, res, next)
{
	var	config = this.config,
		adapter = this.adapter,
		that = this,
		token = req.params.token;

	// if format is wrong no need to query the database
	if(!uuid.isValid(token))
	{
		next();
	}
	else
	{
		// Custom for our app
		var basequery = {};
		if(res.locals && res.locals.basequery)
		{
			basequery = res.locals.basequery;
		}

		// check if we have a user with that token
		adapter.find('pwdResetToken', token, function(err, user)
			{
				if(err)
				{
					next(err);
				}
				else if(!user)
				{
					// if no user is found forward to error handling middleware
					next();
				}
				else
				{
					// check if token has expired
					if(new Date(user.pwdResetTokenExpires) < new Date())
					{
						// make old token invalid
						delete user.pwdResetToken;
						delete user.pwdResetTokenExpires;

						// update user in db
						adapter.update(user, function(err, user)
							{
								if(err)
								{
									next(err);
								}
								else
								{
									that.sendResponse({message:'The link has expired'}, config.forgotPassword.views.linkExpired, user, {result:true}, req, res, next);
								}
							});
					}
					else
					{
						that.sendResponse(undefined, config.forgotPassword.views.newPassword, user, {token:token,result:true}, req, res, next);
					}
				}
			}, basequery);
	}
};



/**
 * POST /forgot-password/:token
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
ForgotPassword.prototype.postToken = function(req, res, next)
{
	var	config = this.config,
		adapter = this.adapter,
		that = this,
		password = req.body.password,
		token = req.params.token,
		error;

	// if format is wrong no need to query the database
	if(!uuid.isValid(token))
	{
		next();
	}
	else if(!password)
	{
		// check for valid input
		that.sendResponse({message:'Please enter a password'}, config.forgotPassword.views.newPassword, undefined, {token:token,result:true}, req, res, next);
	}
	else
	{
		// Custom for our app
		var basequery = {};
		if(res.locals && res.locals.basequery)
		{
			basequery = res.locals.basequery;
		}

		// check for token in db
		adapter.find('pwdResetToken', token, function(err, user)
			{
				if(err)
				{
					next(err);
				}
				else
				{
					// if no token is found forward to error handling middleware
					if(!user)
					{
						next();
					}
					else
					{
						// check if token has expired
						if(new Date(user.pwdResetTokenExpires) < new Date())
						{
							// make old token invalid
							delete user.pwdResetToken;
							delete user.pwdResetTokenExpires;

							// update user in db
							adapter.update(user, function(err, user)
								{
									if(err)
									{
										next(err);
									}
									else
									{
										that.sendResponse({message:'The link has expired'}, config.forgotPassword.views.linkExpired, user, {result:true}, req, res, next);
									}
								});
						}
						else
						{
							// if user comes from couchdb it has an 'iterations' key
							if(user.iterations)
							{
								pwd.iterations(user.iterations);
							}

							// create hash for new password
							pwd.hash(password, function(err, salt, hash)
								{
									if(err)
									{
										return next(err);
									}

									// update user's credentials
									user.salt = salt;
									user.derived_key = hash;

									// remove helper properties
									delete user.pwdResetToken;
									delete user.pwdResetTokenExpires;

									// update user in db
									adapter.update(user, function(err, user)
										{
											if(err)
											{
												next(err);
											}
											else
											{
												that.sendResponse(undefined, config.forgotPassword.views.changedPassword, user, {result:true}, req, res, next);
											}
										});

								});
						}
					}
				}
			}, basequery);
	}
};