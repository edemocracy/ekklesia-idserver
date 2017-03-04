# -*- coding: utf-8 -*-
#
# URL definitions
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

from django.conf.urls import include, url
from django.views.generic import TemplateView
import accounts.views as views
import accounts.forms as forms
import django.contrib.auth.views as auth
from ekklesia.views import logout_delay
from django_otp.forms import OTPAuthenticationForm

urlpatterns = [
    url(r'^$', views.index_view, name='index'),
    #url(r'^login/$', 'django.contrib.auth.views.login', {'template_name': 'registration/login.html'},name='login'),
    url(r'^otplogin/$', views.otp_login,name='otplogin'),
    url(r'^logout/$', logout_delay, {'next_page':'/', 'redirect_delay': 5 },name='logout'),

    url(r'^password_reset/$', views.password_reset, name='password_reset'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.password_reset_confirm, name='password_reset_confirm'),

    url(r'^password/$', auth.password_change, dict(template_name=views.default_template,
        password_change_form=forms.PasswordChangeForm,post_change_redirect='/'),name='password'),
    url(r'^username/$',views.username_change,name='username'),
    url(r'^email/$',views.email_change,name='email'),
    url(r'^profile/$',views.profile_view,name='profile'),
    url(r'^editprofile/$',views.profile_edit,name='profile_edit'),
    url(r'^departments/$', views.show_departments,name='departments'),

    url(r'^register/$', views.MemberRegistrationView.as_view(), name='register'),
    url(r'^signup/$', views.GuestRegistrationView.as_view(), name='signup'),
    # Confirmation keys get matched by \w+ instead of the more specific
    # [a-fA-F0-9]{40} because a bad confirmation key should still get to the view;
    # that way it can return a sensible "invalid key" message instead of a
    # confusing 404.
    url(r'^confirm/(?P<confirmation_key>\w+)/$', views.EMailConfirmationView.as_view(),
         name='email_confirmation'),

    url(r'', include('django.contrib.auth.urls')),
]
