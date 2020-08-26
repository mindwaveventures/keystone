var compression = require('compression');
var favicon = require('serve-favicon');
var methodOverride = require('method-override');
var morgan = require('morgan');

var language = require('../lib/middleware/language');

module.exports = function createApp (keystone, express) {

	if (!keystone.app) {
		if (!express) {
			express = require('express');
		}
		keystone.app = express();
	}

	var app = keystone.app;
	
	//Intialize the header for secuirty issues in keystone
	app.use(function (req, res, next) {
	  res.header('X-Content-Type-Options', 'nosniff');
    res.header('Referrer-Policy', 'no-referrer');
    res.header('X-Permitted-Cross-Domain-Policies', 'none');
		res.header('X-Frame-Options', 'SAMEORIGIN');
		res.header('X-XSS-Protection', '0');
		res.header('Strict-Transport-Security', ' max-age=31536000');
		res.header("Content-Security-Policy", "default-src *; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'");
		res.header('Feature-Policy', 'none');
		res.removeHeader('X-Powered-By');
		res.removeHeader('Server');
		next()
	});
	
	require('./initLetsEncrypt')(keystone, app);
	require('./initSslRedirect')(keystone, app);

	keystone.initDatabaseConfig();
	keystone.initExpressSession(keystone.mongoose);

	require('./initTrustProxy')(keystone, app);
	require('./initViewEngine')(keystone, app);
	require('./initViewLocals')(keystone, app);
	require('./bindIPRestrictions')(keystone, app);

	// Compress response bodies
	if (keystone.get('compress')) {
		app.use(compression());
	}

	// Pre static config
	if (typeof keystone.get('pre:static') === 'function') {
		keystone.get('pre:static')(app);
	}
	app.use(function (req, res, next) {
		keystone.callHook('pre:static', req, res, next);
	});

	// Serve static assets

	if (keystone.get('favicon')) {
		app.use(favicon(keystone.getPath('favicon')));
	}

	// unless the headless option is set (which disables the Admin UI),
	// bind the Admin UI's Static Router for public resources
	if (!keystone.get('headless')) {
		app.use('/' + keystone.get('admin path'), require('../admin/server').createStaticRouter(keystone));
	}

	require('./bindLessMiddleware')(keystone, app);
	require('./bindSassMiddleware')(keystone, app);
	require('./bindStylusMiddleware')(keystone, app);
	require('./bindStaticMiddleware')(keystone, app);
	require('./bindSessionMiddleware')(keystone, app);

	// Log dynamic requests
	app.use(function (req, res, next) {
		keystone.callHook('pre:logger', req, res, next);
	});
	// Bind default logger (morgan)
	if (keystone.get('logger')) {
		var loggerOptions = keystone.get('logger options');
		var hasOwnProperty = Object.prototype.hasOwnProperty;
		if (loggerOptions && typeof loggerOptions.tokens === 'object') {
			for (var key in loggerOptions.tokens) {
				if (hasOwnProperty.call(loggerOptions.tokens, key) && typeof loggerOptions.tokens[key] === 'function') {
					morgan.token(key, loggerOptions.tokens[key]);
				}
			}
		}

		app.use(morgan(keystone.get('logger'), loggerOptions));
	}
	// Bind custom logging middleware
	if (keystone.get('logging middleware')) {
		app.use(keystone.get('logging middleware'));
	}

	// unless the headless option is set (which disables the Admin UI),
	// bind the Admin UI's Dynamic Router
	if (!keystone.get('headless')) {
		if (typeof keystone.get('pre:admin') === 'function') {
			keystone.get('pre:admin')(app);
		}
		app.use(function (req, res, next) {
			keystone.callHook('pre:admin', req, res, next);
		});
		app.use('/' + keystone.get('admin path'), require('../admin/server').createDynamicRouter(keystone));
	}

	// Pre bodyparser middleware
	if (typeof keystone.get('pre:bodyparser') === 'function') {
		keystone.get('pre:bodyparser')(app);
	}
	app.use(function (req, res, next) {
		keystone.callHook('pre:bodyparser', req, res, next);
	});

	require('./bindBodyParser')(keystone, app);
	app.use(methodOverride());

	// Set language preferences
	var languageOptions = keystone.get('language options') || {};
	if (!languageOptions.disable) {
		app.use(language(keystone));
	}

	// Add 'X-Frame-Options' to response header for ClickJacking protection
	if (keystone.get('frame guard')) {
		app.use(require('../lib/security/frameGuard')(keystone));
	}

	// Pre route config
	if (typeof keystone.get('pre:routes') === 'function') {
		keystone.get('pre:routes')(app);
	}
	app.use(function (req, res, next) {
		keystone.callHook('pre:routes', req, res, next);
	});

	// Configure application routes
	var appRouter = keystone.get('routes');
	if (typeof appRouter === 'function') {
		if (appRouter.length === 3) {
			// new:
			//    var myRouter = new express.Router();
			//    myRouter.get('/', (req, res) => res.send('hello world'));
			//    keystone.set('routes', myRouter);
			app.use(appRouter);
		} else {
			// old:
			//    var initRoutes = function (app) {
			//      app.get('/', (req, res) => res.send('hello world'));
			//    }
			//    keystone.set('routes', initRoutes);
			appRouter(app);
		}
	}


	require('./bindRedirectsHandler')(keystone, app);

	// Error config
	if (typeof keystone.get('pre:error') === 'function') {
		keystone.get('pre:error')(app);
	}
	app.use(function (req, res, next) {
		keystone.callHook('pre:error', req, res, next);
	});
	require('./bindErrorHandlers')(keystone, app);

	return app;

};
