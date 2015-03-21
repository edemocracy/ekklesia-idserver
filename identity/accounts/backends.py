# -*- coding: utf-8 -*-
#
# Auth backends
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

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class UserOrEmailAuthBackend(ModelBackend):
    """
    Username/Email Authentication Backend

    Allows a user to sign in using an email/password pair rather than
    a username/password pair.
    """
    supports_anonymous_user=False

    def authenticate(self, username=None, password=None, **kwargs):
        #If username is an email address, then try to pull it up
        from django.core.validators import email_re
        User = get_user_model()
        if email_re.search(username):
            try:
                user = User.objects.get(email__iexact=username)
            except User.DoesNotExist:
                return None
        else:
            #We have a non-email address username we should try username
            try:
                user = User.objects.get(username__iexact=username)
            except User.DoesNotExist:
                return None
        return user