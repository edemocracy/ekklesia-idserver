# -*- coding: utf-8 -*-
#
# Views
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

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.shortcuts import resolve_url
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.utils.translation import ugettext as _

def logout_delay(request, next_page=None,
           template_name='registration/logged_out.html',
           redirect_field_name=REDIRECT_FIELD_NAME,
           current_app=None, extra_context=None, redirect_delay=0):
    """
    Logs out the user and displays 'You are logged out' message.
    """
    from django.contrib.auth.views import logout
    from django.utils.http import is_safe_url

    if not extra_context: extra_context = {}
    extra_context = dict(extra_context)
    extra_context['redirect_delay'] = redirect_delay

    response = logout(request, next_page, template_name, redirect_field_name,
           current_app, extra_context)
    if not redirect_delay: return response

    if next_page is not None:
        next_page = resolve_url(next_page)

    if redirect_field_name in request.REQUEST:
        next_page = request.REQUEST[redirect_field_name]
        # Security check -- don't allow redirection to a different host.
        if not is_safe_url(url=next_page, host=request.get_host()):
            next_page = request.path

    response['Refresh'] = '%s; url=%s' % (redirect_delay,next_page)
    return response
