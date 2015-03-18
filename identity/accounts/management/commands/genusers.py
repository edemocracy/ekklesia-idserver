# -*- coding: utf-8 -*-
#
# Generate test users
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

from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import ugettext as _
from django.contrib.auth import get_user_model
User = get_user_model()

class Command(BaseCommand):
    help = 'generate users'

    def handle(self, *args, **options):
        for i in range(100):
            user = User(username='user%i'%i)
            user.first_name='foo'
            user.last_name=str(i)
            user.email='foo.%i@bar.com' % i
            user.save()
        print('done')
