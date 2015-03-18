from __future__ import absolute_import

from django.conf import settings
import os, configurations

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'identity.settings')
os.environ.setdefault('DJANGO_CONFIGURATION', 'Development')

try: configurations.setup()
except:
    from configurations.importer import install
    install()

if settings.USE_CELERY:
    # This will make sure the app is always imported when
    # Django starts so that shared_task will use this app.
    from .celery import app as celery_app
