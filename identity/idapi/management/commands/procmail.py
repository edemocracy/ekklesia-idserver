# -*- coding: utf-8 -*-
#
# Store email
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

    args = '[options] [identity]'
    help = 'store email'

    option_list = BaseCommand.option_list + (
        make_option("-d", "--decrypt", action="store_true", default=False,
            help="decrypt and verify message immediately"),
        make_option("-f", "--file", help="ready input from file"),
        )

    def handle(self, *args, **options):
        from idapi.mails import store_mail
        import os, sys
        if len(args)>1:
            raise CommandError('invalid number of arguments')
        if len(args)==1:
            identity = args[0] 
            if not identity in settings.EMAIL_IDS:
                raise CommandError('unknown identity')
        else: identity = None
        if options['file']: # read from file
            if not os.path.exists(options['file']):
                raise CommandError('input file does not exist')
            msg = open(options['file'],'rt').read()
        else:
            msg = sys.stdin.read()
        if not msg:
            raise CommandError('input is missing')
        result = store_mail(msg,identity,decrypt=options['decrypt'])
        if not result:
            raise CommandError('failed')
        self.stdout.write('success')
