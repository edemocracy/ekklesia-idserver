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

from django.conf.urls import patterns, include, url
from django.conf import settings
from django.conf.urls.static import static

from django.contrib import admin
admin.autodiscover()

from accounts.admin import verification_site
import accounts.views

SITE_ID = getattr(settings, 'SITE_ID', 0)

urlpatterns = []
if SITE_ID != 2: # main, not for API-only
    urlpatterns += [
        url(r'^oauth2/authorize/$', accounts.views.IDAuthorizationView.as_view(), name="authorize"),
        url(r'^oauth2/', include('oauth2_provider.urls', namespace='oauth2_provider')),
        url(r'', include('accounts.urls', namespace="accounts")),
    ]
# API
urlpatterns += [
    url(r'^api/v1/', include('idapi.urls', namespace="v1")),
]
if getattr(settings, 'DEBUG', False):
    urlpatterns += [
        url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
        url(r'^api-docs/', include('rest_framework_swagger.urls')),
    ]+static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
#urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

if getattr(settings, 'HAVE_ADMIN', False):
    urlpatterns += [
        url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
        url(r'^admin/', include(admin.site.urls)),
        url(r'^verification/', include(verification_site.urls)),
    ]
