# -*- coding: utf-8 -*-
#
# Admin
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

from django.contrib.auth.forms import AuthenticationForm
from django import forms
from django.contrib.auth import authenticate
from django.utils.translation import ugettext_lazy as _
from django.contrib.admin.sites import AdminSite

class UserAdminAuthenticationForm(AuthenticationForm):
    """
    Same as Django's AdminAuthenticationForm but allows to login
    any user who is not staff.
    """
    this_is_the_login_form = forms.BooleanField(widget=forms.HiddenInput, initial=1,
        error_messages={'required': _("Please log in again, because your session has expired.")})

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        from django.contrib.admin.forms import ERROR_MESSAGE
        message = ERROR_MESSAGE

        if username and password:
            self.user_cache = authenticate(username=username, password=password)
            if self.user_cache is None:
                raise forms.ValidationError(message % {
                    'username': self.username_field.verbose_name
                })
            elif not self.user_cache.is_active: #or not self.user_cache.is_staff:
                raise forms.ValidationError(message % {
                    'username': self.username_field.verbose_name
                })
        return self.cleaned_data

class UserAdminSite(AdminSite):
    login_form = UserAdminAuthenticationForm

    def __init__(self, perm='',*args,**kwargs): 
        super(UserAdminSite,self).__init__(*args,**kwargs)
        self.perm = perm

    def has_permission(self, request):
        """
        Removed check for is_staff.
        """
        return request.user.is_active and (not self.perm or request.user.has_perm(self.perm))

    def addcontext(self,request,extra_context=None):
        useradmin = {'useradmin':self.has_permission(request)}
        if extra_context is None: extra_context = {}
        extra_context.update(useradmin)

    def login(self, request, extra_context=None):
        return super(UserAdminSite,self).login(request,self.addcontext(request,extra_context))

    def logout(self, request, extra_context=None):
        return super(UserAdminSite,self).logout(request,self.addcontext(request,extra_context))

    def index(self, request, extra_context=None):
        return super(UserAdminSite,self).index(request,self.addcontext(request,extra_context))

    def app_index(self, request, app_label, extra_context=None):
        return super(UserAdminSite,self).app_index(request,app_label,self.addcontext(request,extra_context))
