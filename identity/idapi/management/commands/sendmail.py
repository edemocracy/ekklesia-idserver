# -*- coding: utf-8 -*-
#
# Send email to user
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

    args = '[options] user [identity subject body]'
    help = 'send email to user'

    option_list = BaseCommand.option_list + (
        make_option("-e", "--encrypt", action="store_true", default=False, help="encrypt message"),
        make_option("-s", "--sign", action="store_true", default=False, help="sign message"),
        make_option("-d", "--direct", action="store_false", dest="queue", default=None, help="send directly"),
        make_option("-q", "--queue", action="store_true", dest="queue", default=None, help="queue"),
        make_option("-f", "--file", help="ready input from file"),
        )

    def handle(self, *args, **options):
        from idapi.mails import send_mail
        from accounts.models import Account
        from json import load
        import os, sys
        if len(args)<1:
            raise CommandError('user argument missing')
        if not len(args) in (1,4):
            raise CommandError('invalid number of arguments')
        user = args[0]
        search = dict(email=user) if user.find('@')>0 else dict(username=user)
        try: user = Account.objects.get(**search)
        except Account.DoesNotExist:
            raise CommandError('user not found')
        if options['file']: # read from file
            if not os.path.exists(options['file']):
                raise CommandError('input file does not exist')
            f = open(options['file'],'rt')
            data = load(f)
            if options['sign']: data['sign'] = True
            if options['encrypt']: data['encrypt'] = True
        elif len(args)==1: # read from file/input
            data = load(sys.stdin)
        else:
            data = dict(identity=args[1],content=dict(subject=args[2],body=args[3]),
                sign=options['sign'],encrypt=options['encrypt']) # template
        if not data:
            raise CommandError('input is missing')
        if not 'identity' in data:
            raise CommandError('identity not specified')
        if not data['identity'] in settings.EMAIL_IDS:
            raise CommandError('unknown identity')
        if not 'content' in data:
            raise CommandError('content is missing')
        if not options['queue'] is None:
            settings.EMAIL_QUEUE = options['queue']
        result = send_mail(data, user, None)
        if result['status'] == 'failed':
            raise CommandError('sending failed')
        self.stdout.write(result['status'])
