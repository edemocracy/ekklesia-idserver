# Django settings for Ekklesia project.

"""
This file is public domain.
"""

import os.path
from configurations import Configuration

all_verbs = ['options','head','get','post','patch','put','delete']
site_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
top_root = os.path.dirname(site_root)

_default_loaders = (
	'django.template.loaders.filesystem.Loader',
	'django.template.loaders.app_directories.Loader',
	'django.template.loaders.eggs.Loader',
)

def defaults(production=False,admin=False,site=0):
	class Defaults(Configuration):
		HAVE_ADMIN = admin
		DEBUG = not production
		SITE_ID = site

		SITE_ROOT = site_root
		TOP_ROOT = top_root

		# default database
		DATABASES = {
			'default': {
				'ENGINE': 'django.db.backends.sqlite3', # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
				'NAME': os.path.join(SITE_ROOT, 'local.db'), # Or path to database file if using sqlite3.
				'USER': '',					  # Not used with sqlite3.
				'PASSWORD': '',				  # Not used with sqlite3.
				'HOST': '',					  # Set to empty string for localhost. Not used with sqlite3.
				'PORT': '',					  # Set to empty string for default. Not used with sqlite3.
			}
		}

		CONN_MAX_AGE = 5*60 # 5minutes

		HOSTNAME='localhost'
		EMAIL_HOST='localhost'
		SECRET_KEY='foobar'

		TEMPLATE_DEBUG = DEBUG
		MEDIA_ROOT = os.path.join(SITE_ROOT, 'media','')
		if production:
			HTTPS_SUPPORT = True
			SESSION_COOKIE_SECURE = True
			CSRF_COOKIE_SECURE = True
			RECAPTCHA_USE_SSL = True
			# Absolute filesystem path to the directory that will hold user-uploaded files.
			# Example: "/home/media/media.lawrence.com/media/"

			EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
			KEY_PREFIX = 'ekklesia'

			CACHES = {
				'default': {
					'BACKEND': 'django.core.cache.backends.memcached.PyLibMCCache',
					'LOCATION': 'localhost:11211',
				}
			}
			PASSWORD_HASHERS = (
				'django_scrypt.hashers.ScryptPasswordHasher',
				'django.contrib.auth.hashers.BCryptPasswordHasher',
				'django.contrib.auth.hashers.PBKDF2PasswordHasher',
			#	'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
			#	'django.contrib.auth.hashers.SHA1PasswordHasher',
			#	'django.contrib.auth.hashers.MD5PasswordHasher',
			#	'django.contrib.auth.hashers.CryptPasswordHasher',
			)
		else:
			HTTPS_SUPPORT = False
			#MEDIA_ROOT = '/tmp/ekklesia-upload/'
			EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
			PASSWORD_HASHERS = ('django.contrib.auth.hashers.MD5PasswordHasher','django.contrib.auth.hashers.PBKDF2PasswordHasher')
			# quicker

		SESSION_COOKIE_AGE = 3600 # 1h in seconds

		# Local time zone for this installation. Choices can be found here:
		# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
		# although not all choices may be available on all operating systems.
		# In a Windows environment this must be set to your system time zone.
		TIME_ZONE = 'Europe/Berlin'

		# Language code for this installation. All choices can be found here:
		# http://www.i18nguy.com/unicode/language-identifiers.html
		LANGUAGE_CODE = 'de-de'
		LANGUAGES = (
			('en', 'English'),
			('de', 'Deutsch'),
		)

		# Hosts/domain names that are valid for this site; required if DEBUG is False
		# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
		ALLOWED_HOSTS = ['127.0.0.1', '::1']

		# If you set this to False, Django will make some optimizations so as not
		# to load the internationalization machinery.
		USE_I18N = True

		# If you set this to False, Django will not format dates, numbers and
		# calendars according to the current locale.
		USE_L10N = True

		# If you set this to False, Django will not use timezone-aware datetimes.
		USE_TZ = True

		ROOT_URLCONF = 'identity.urls'

		# Python dotted path to the WSGI application used by Django's runserver.
		WSGI_APPLICATION = 'identity.wsgi.application'

		INSTALLED_APPS = (
			'django.contrib.auth',
			'django.contrib.contenttypes',
			'django.contrib.sessions',
			'django.contrib.messages',
			'django.contrib.staticfiles',
			#'django.contrib.formtools', # for previews
			#'django.contrib.sitemaps', # for XML sitemap
			'django.contrib.humanize',
			'mptt',
			'django_extensions',
			#'endless_pagination',
			'oauth2_provider',
			'corsheaders',
			'rest_framework',
			#'rest_framework.authtoken',
			#'rest_framework_digestauth',
			'crispy_forms',
			'captcha',
			'django_otp',
			'django_otp.plugins.otp_email',
			#'phonenumber_field',
			'django_countries',
			'identity',
			'accounts',
			'idapi',
		)
		if SITE_ID:
			INSTALLED_APPS += ('django.contrib.sites',)
		if admin:
			INSTALLED_APPS += ('django_admin_bootstrapped.bootstrap3','django_admin_bootstrapped',
				'django.contrib.admin','django.contrib.admindocs')
		if DEBUG:
			INSTALLED_APPS += ('rest_framework_swagger',)

		MIDDLEWARE_CLASSES = (
			#'django.middleware.cache.UpdateCacheMiddleware',
			'ekklesia.middleware.SecureRequiredMiddleware',
			'django.middleware.gzip.GZipMiddleware',
			'django.middleware.common.CommonMiddleware',
			#'django.middleware.http.ConditionalGetMiddleware',
			'django.contrib.sessions.middleware.SessionMiddleware',
			'django.middleware.csrf.CsrfViewMiddleware',
			#'django.middleware.locale.LocaleMiddleware',
			'django.contrib.auth.middleware.AuthenticationMiddleware',
			'django.contrib.messages.middleware.MessageMiddleware',
			'django_otp.middleware.OTPMiddleware',
			# Uncomment the next line for simple clickjacking protection:
			'django.middleware.clickjacking.XFrameOptionsMiddleware',
			#'django.middleware.cache.FetchFromCacheMiddleware',
			'corsheaders.middleware.CorsMiddleware',
		)

		AUTH_USER_MODEL = 'accounts.Account'

		AUTHENTICATION_BACKENDS=(
			'django.contrib.auth.backends.ModelBackend',
			#'accounts.backends.UserOrEmailAuthBackend',
		)

		#DEFAULT_CONTENT_TYPE = 'application/xhtml+xml'

		CRISPY_TEMPLATE_PACK = 'bootstrap3'

		OAUTH2_PROVIDER = { # this is the list of available scopes
			'SCOPES': { # none = login only = has account
				'unique': 'app-specific unique user id',
				'member': 'membership information',
				'profile': 'personal profile',
				'mail': 'mail support',
			}
		}

		OAUTH2_PROVIDER_APPLICATION_MODEL = 'idapi.IDApplication'

		CORS_ORIGIN_ALLOW_ALL = True # FIXME

		REST_FRAMEWORK = {
			'DEFAULT_AUTHENTICATION_CLASSES': (
				'oauth2_provider.ext.rest_framework.OAuth2Authentication',
				'rest_framework.authentication.SessionAuthentication',
		#	   'rest_framework_digestauth.authentication.DigestAuthentication',
			),
			'DEFAULT_PERMISSION_CLASSES': (
				'rest_framework.permissions.IsAdminUser',
				'rest_framework.permissions.IsAuthenticated',
			),
			'PAGINATE_BY': 10,
		}

		SWAGGER_SETTINGS = {
			"exclude_namespaces": [], # List URL namespaces to ignore
			"api_version": '1.0',  # Specify your API's version
			"api_path": "/api/v1",  # Specify the path to your API not a root level
			"enabled_methods": [  # Specify which methods to enable in Swagger UI
				'get',
				'post',
				'put',
				'patch',
				'delete'
			],
			"api_key": '', # An API key
			"is_authenticated": False,  # Set to True to enforce user authentication,
			"is_superuser": False,  # Set to True to enforce admin only access
		}

		#APPEND_SLASH = False

		# URL that handles the media served from MEDIA_ROOT. Make sure to use a
		# trailing slash.
		# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
		MEDIA_URL = '/media/'

		# Absolute path to the directory static files should be collected to.
		# Don't put anything in this directory yourself; store your static files
		# in apps' "static/" subdirectories and in STATICFILES_DIRS.
		# Example: "/home/media/media.lawrence.com/static/"
		STATIC_ROOT = os.path.join(SITE_ROOT, 'static.prod','')

		# URL prefix for static files.
		# Example: "http://media.lawrence.com/static/"
		STATIC_URL = '/static/' #if DEBUG else 'https://%s/static/' % HOSTNAME

		# Additional locations of static files
		STATICFILES_DIRS = (
			# Put strings here, like "/home/html/static" or "C:/www/django/static".
			# Always use forward slashes, even on Windows.
			# Don't forget to use absolute paths, not relative paths.
			os.path.join(SITE_ROOT, 'static'),
			os.path.join(TOP_ROOT, 'static'),
		)

		# List of finder classes that know how to find static files in
		# various locations.
		STATICFILES_FINDERS = (
			'django.contrib.staticfiles.finders.FileSystemFinder',
			'django.contrib.staticfiles.finders.AppDirectoriesFinder',
		#	'django.contrib.staticfiles.finders.DefaultStorageFinder',
		)

		# Cache busting. Does nothing in development mode
		STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.CachedStaticFilesStorage'

		TEMPLATE_CONTEXT_PROCESSORS = (
			"django.contrib.auth.context_processors.auth",
			"django.core.context_processors.debug",
			"django.core.context_processors.i18n",
			"django.core.context_processors.media",
			"django.core.context_processors.static",
			"django.core.context_processors.tz",
			"django.contrib.messages.context_processors.messages",
			'django.core.context_processors.request',
		)

		# List of callables that know how to import templates from various sources.
		if DEBUG:
			TEMPLATE_LOADERS = (('pyjade.ext.django.Loader',_default_loaders),)
		else:
			TEMPLATE_LOADERS = _default_loaders

		TEMPLATE_DIRS = (
			# Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
			# Always use forward slashes, even on Windows.
			# Don't forget to use absolute paths, not relative paths.
			#os.path.join(SITE_ROOT, 'templates'),
			os.path.join(TOP_ROOT, 'templates.custom'),
			os.path.join(TOP_ROOT, 'templates'),
		)

		if DEBUG: # support proxy for debugging
			# in nginx set:
			# proxy_set_header X-Forwarded-Proto $scheme;
			# proxy_set_header X-Forwarded-Host $host;
			SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
			USE_X_FORWARDED_HOST= True

		SECURE_REQUIRED_PATHS = (
			'/admin/',
			'/api/',
			'/oauth2/',
			'/accounts/',
		)

		CRISPY_FAIL_SILENTLY = not DEBUG
		LOGGING = {
			'version': 1,
			'disable_existing_loggers': False,
			'formatters': {
				'verbose': {
					'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
				},
				'simple': {
					'format': '%(levelname)s %(message)s'
				},
			},
			'filters': {
				'require_debug_false': {
					'()': 'django.utils.log.RequireDebugFalse'
				},
				'require_debug_true': {
					'()': 'django.utils.log.RequireDebugTrue',
				},
			},
			'handlers': {
				'null': {
					'level': 'DEBUG',
					'class': 'logging.NullHandler',
				},
				'console':{
					'level': 'DEBUG',
					'class': 'logging.StreamHandler',
					'filters': ['require_debug_true'],
					'formatter': 'verbose'
				},
				'file': {
					'level': 'DEBUG',
					'class': 'logging.FileHandler',
					'filename': 'debug.log',
				},
				'mail_admins': {
					'level': 'ERROR',
					'filters': ['require_debug_false'],
					'class': 'django.utils.log.AdminEmailHandler'
				},
			},
			'loggers': {
				'django': {
					'handlers': ['file'],
					'level': 'DEBUG',
					'propagate': True,
				},
				'django.request': {
					'handlers': ['console'],
					'level': 'DEBUG',
					'propagate': True,
				},
				'django.request': {
					'handlers': ['mail_admins'],
					'level': 'ERROR',
					'propagate': True,
				},
				'django.db.backends': {
					'handlers': ['file'],
					'level': 'INFO',
					'propagate': True,
				},
				'oauth2_provider': {
					'handlers': ['file'],
					'level': 'DEBUG',
					'propagate': True,
				},
				'oauthlib': {
					'handlers': ['file'],
					'level': 'DEBUG',
					'propagate': True,
				},
				'debug': {
					'handlers': ['file'],
					'level': 'DEBUG',
				},
			},
		}

		#----------------------------------------------------------------------
		# App config

		LOGIN_URL = '/'
		LOGIN_REDIRECT_URL = '/'
		LOGIN2FAC_URL = '/otplogin/'
		TOS_URL = '/tos/'

		SSL_CLIENT_AUTH_DEBUG = False # True disables cert checks

		# cert files must have a final newline!
		SSL_CERTS = {
		}

		SSL_BASIC_AUTH = {
			# realm. logins (SSL-Cert,user,password) username=None use realm
		}

		SSL_CLIENT_LOGIN = {
			# SSL-Cert: permitted client_ids
		}

		SHARE_CLIENTS = {
			# share name, {client_id: allowed VERBS}
		}

		SHARE_PUSH = {
			# share name, [push urls]
		}

		CACERT_BUNDLE='' # CA CERT bundle

		# own gnupg key (id,passphrase) for signing and decryption
		API_GNUPG_KEY = None
		# gnupg keys backend:(id,passphrase) for verfication and encryption
		API_BACKEND_KEYS = {}

		REGISTRATION_OPEN = True
		REGISTRATION_CLOSED_URL = '/' # url if registration is closed

		INVITATIONS_DELETE_IMPLICT = False # whether to delete members whose uuid was not uploaded

		# home of id keyrings or tuple of keyrings file of id public/secret keys
		# default $HOME/.gnupg
		EMAIL_GPG_IMPORT_HOME = None
		# own working home (default SITE_ROOT)
		EMAIL_GPG_HOME = None

		EMAIL_INDEP_CRYPTO = False # run independent crypto processing for incoming/outgoing mail

		EMAIL_TEMPLATES = {
			# name: (subject,body) string(=default Template) or Template
		}

		EMAIL_DEFAULT_IMAP=dict(host='localhost',port=993,user=None,password=None,
			cram_md5=True,certfile=None,keyfile=None,ca_certs=None)

		EMAIL_DEFAULT_SMTP=dict(host='localhost',port=25,user=None,password=None,
			certfile=None,keyfile=None,ca_certs=None)

		""" id: (
			'email':None=id, # optional, default=id
			'name':'', # optional
			'key':(keyid(None=email), passphrase), # optional
			'login':(user(None=email),passphrase), # optional default for IMAP/SMTP
			'imap':dict, # optional
			'imapdir':'', # optional
			'smtp':dict, # optional
			'templates:':[default templates] # optional
			)
		"""
		EMAIL_IDS = {
		}

		EMAIL_REGISTER_ID = None # id of key registry

		EMAIL_CLIENTS = {
			# client_id: {id:(recieve,sending(False=no,True=all templates,None=default tmpl),attachments)
		}

		EMAIL_CONFIRMATION_DAYS = 1
		REGISTRATION_OPEN = True
		CAPTCHA_AJAX = False
		RECAPTCHA_PUBLIC_KEY=""
		RECAPTCHA_PRIVATE_KEY=""

		TWO_FACTOR_SIGNUP=False
		# member signup with invitation code, unique username, password, captcha and email confirmation
		# False=no extra information
		# True=require extra value to be checked by memberdb

		TWO_FACTOR_AUTH=False
		# False=username and passphrase sufficient
		# 'code'=send code per registered email for username+password, login with code/URL+passphrase

		NOTIFY_AUTH=False # False=disabled,'optional'=user specific setting, True=always

		BROKER_URL = 'amqp://'
		BROKER_USE_SSL= False
		CELERY_RESULT_BACKEND = 'amqp://'
		CELERY_TASK_SERIALIZER = 'json'
		CELERY_RESULT_SERIALIZER = 'json'
		CELERY_ACCEPT_CONTENT=['json']
		CELERY_TIMEZONE = 'Europe/Berlin'
		CELERY_ENABLE_UTC = True
	return Defaults

class Testing(defaults(production=True,admin=False)):
	#SSL_CLIENT_AUTH_DEBUG = 'local'

	PASSWORD_HASHERS = ('django.contrib.auth.hashers.MD5PasswordHasher',)
	SECURE_REQUIRED_PATHS = ()
	CACHES = {
		'default': {
			'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
		}
	}
	STATICFILES_STORAGE = ''
	SSL_CERTS = {
		'FAKE CERT\n':'fake',
	}

	SSL_CLIENT_LOGIN = {
		# SSL-Cert: permitted client_ids
		'fake':('portal','debug'),
	}

	SSL_BASIC_AUTH = {
		# realm. logins (SSL-Cert,user,password) username=None use realm
		'invitations': [('fake','invitations','invitations')],
		'members': [('fake','members','members')],
	}

	SHARE_CLIENTS = {
		# share name, {client_id: allowed VERBS}
		'test': {'portal':all_verbs,'debug':all_verbs,'voting':['get']},
		'portal': {'portal':all_verbs,'voting':['get']},
		'voting': {'voting':all_verbs,'portal':['get']},
	}

	LISTS_CLIENTS = {
		# client_id: allowed VERBS
		'portal':all_verbs,'debug':all_verbs,
	}

	SHARE_PUSH = {
		# share name, [push urls]
		'portal': ['https://localhost/pushshare/'],
	}

	EMAIL_TEMPLATES = {
		# name: (subject,body) string(=default Template) or Template
		'register_confirm': ('Registration',
	"""Please confirm your key either by clicking on {url}={code}
	or enter the following code at {url}: {code}
	Thank you"""),
	}

	EMAIL_IDS = {
		'portal': dict(
			email='foo@localhost',
			name='Portal',
			login=(None,'foo'),
			key=(None,'mysecret'),
			),
		'register': dict(
			email='fnord@localhost',
			login=('foo@localhost','foo'),
			templates=['register_confirm'],
			),
	}
	EMAIL_REGISTER_ID = 'portal' # id of key registry

	EMAIL_CLIENTS = {
		# client_id: {id:(recieve,sending(False=no,True=all templates,None=default tmpl),attachments)
		'portal': {'portal':(True,None,True)},
		'debug': {'portal':(True,True,True)},
	}

	EMAIL_GPG_IMPORT_HOME = (site_root+'/ekklesia/tests/pubring.gpg',site_root+'/ekklesia/tests/secring0.gpg')
	EMAIL_GPG_HOME = None # should not be used

	BROKER_URL = None

	# own gnupg key (id,passphrase) for signing and decryption
	API_GNUPG_KEY = ('foo@localhost','mysecret')
	# gnupg keys backend:(id,passphrase) for verfication and encryption
	API_BACKEND_KEYS = {'members':'bar@localhost','invitations':'bar@localhost'}
