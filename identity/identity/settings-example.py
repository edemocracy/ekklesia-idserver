# Django settings for Ekklesia project.

"""
This file is public domain.
"""

from __future__ import absolute_import
import os.path, logging, ssl
from ekklesia.mail import Template
from identity.defaults import defaults, all_verbs, site_root, top_root
from identity.defaults import Testing as DefaultTesting

def common(production=False,admin=False,site=0):
	class Common(defaults(production,admin,site)):
		pass
	return Common

# Testing settings
class Testing(DefaultTesting):
	pass

# Development settings
class Development(common(production=False,admin=True)):
	pass

# Development API settings
class DevelopmentAPI(common(production=False,admin=False,site=2)):
	pass

# Production settings
class Production(common(production=True,admin=True,site=1)):
	#with file('/etc/ekklesia-secret') as key_file:
	#	SECRET_KEY = key_file.read()
	pass

# Production API settings
class ProductionAPI(common(production=True,admin=False,site=2)):
	pass
