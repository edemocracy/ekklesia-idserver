# -*- coding: utf-8 -*-
#
# Check email settings
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
from django.conf import settings
from optparse import make_option

class Command(BaseCommand):

    help = 'check email settings'

    def check_config(self):
        from django.conf import settings
        ok = True
        ids = getattr(settings,'EMAIL_IDS')
        if ids:
            seen = {}
            for id, opts in ids.iteritems():
                email = opts.get('email',id)
                if email in seen:
                    print('ids: email %s used for id %s and %s' % (email,id,seen[email]))
                    ok = False
                else:
                    seen[email] = id
        return ok

    def handle(self, *args, **options):
        if self.check_config(): print('success')
        else: print('failed')
