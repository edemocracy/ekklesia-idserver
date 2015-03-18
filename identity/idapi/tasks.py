# -*- coding: utf-8 -*-
#
# Background tasks
#
# Copyright (C) 2013,2014 by entropy@heterarchy.net
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

from __future__ import absolute_import

from django.conf import settings
from celery import task

@task(ignore_result=True)
def send_background(msgid, debug=None, debug_gpg=None):
    from idapi.mails import send_queue
    print 'celery'
    return send_queue(msgid, debug, debug_gpg)

@task(ignore_result=True)
def decrypt_background(msgid):
    from idapi.mails import send_queue
    print 'decrypt msg', msgid
