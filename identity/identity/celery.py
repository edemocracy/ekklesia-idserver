from __future__ import absolute_import

import os

from celery import Celery

from django.conf import settings

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'identity.settings')
os.environ.setdefault('DJANGO_CONFIGURATION', 'Development')

import configurations
try: configurations.setup()
except:
    from configurations.importer import install
    install()

app = Celery('identity')

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object('django.conf:settings')
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
