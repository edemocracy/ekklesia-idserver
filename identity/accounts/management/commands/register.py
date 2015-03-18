# -*- coding: utf-8 -*-
#
# import and export departments
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
from optparse import make_option

class Command(BaseCommand):
    args = '[options] code username email [password]'
    help = 'register a user'
    option_list = BaseCommand.option_list + (
#        make_option('code',help='invitation code or uuid'),
#        make_option('username',help='username'),
#        make_option('email',help='email address'),
#        make_option('password',nargs='?',help='password'),
        make_option('-u','--uuid',action='store_true',default=False,
            help='use UUID instead of invitation code'),
        make_option('-s','--secret',help='activation secret'),
        )

    def handle(self, *args, **options):
        from accounts.models import Account, Invitation, notify_backends
        from django.core.exceptions import ObjectDoesNotExist
        
        assert len(args)>=3, 'arguments missing'
        code, username, email = args[:3]
        password = args[3] if len(args)>3 else None
        try:
            if options['uuid']: inv = Invitation.objects.get(uuid=code)
            else: inv = Invitation.objects.get(code=code)
        except ObjectDoesNotExist:
            print 'invitation not found'
            return
        if Account.objects.filter(username=username).exists():
            print ('username is already used')
            return
        try:
            Account.objects.get(email=email)
            print ('email is already used')
            return
        except ObjectDoesNotExist: pass
        if not password: password = input('enter password:')
        Account.objects.create_user(username, email, password,
                        status=Account.NEWMEMBER, uuid=inv.uuid)
        inv.status = Invitation.REGISTERING
        inv.secret = options['secret'] or None
        inv.save()
        notify_backends(status='registering',uuid=inv.uuid)
        print 'success'
