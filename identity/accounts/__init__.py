# -*- coding: utf-8 -*-
#
# Initialization
#
# Copyright (C) 2013-2015 by Thomas T. <ekklesia@heterarchy.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# For more details see the file COPYING.

from django.db.models.signals import post_migrate
#import accounts.models

def create_permissions(sender, **kwargs):
    from django.contrib.auth.models import Permission
    from django.contrib.contenttypes.models import ContentType
    from django.contrib.contenttypes.management import update_all_contenttypes
    update_all_contenttypes() # make sure all content types exist
    account_content = ContentType.objects.get(app_label='accounts', model='account')
    guest_content = ContentType.objects.get(app_label='accounts', model='guest')
    verification_content = ContentType.objects.get(app_label='accounts', model='verification')
    Permission.objects.get_or_create(codename='profile_change',
                                       name='Can change user profiles',
                                       content_type=account_content)
    Permission.objects.get_or_create(codename='guest_reviews',
                                       name='Can review guest applications',
                                       content_type=guest_content)
    Permission.objects.get_or_create(codename='account_verify',
                                       name='Can verifiy accounts',
                                       content_type=verification_content)


#post_migrate.connect(create_permissions, sender=accounts.models)
