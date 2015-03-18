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
from idapi import views, appviews
from idapi import backendviews
from rest_framework import routers
#from rest_framework.urlpatterns import format_suffix_patterns

class HeadRouter(routers.DefaultRouter):
    routes = [
        # List route.
        routers.Route(
            url=r'^{prefix}{trailing_slash}$',
            mapping={
                'head': 'list',
                'get': 'list',
                'post': 'create'
            },
            name='{basename}-list',
            initkwargs={'suffix': 'List'}
        ),
        # Detail route.
        routers.Route(
            url=r'^{prefix}/{lookup}{trailing_slash}$',
            mapping={
                'head': 'retrieve',
                'get': 'retrieve',
                'put': 'update',
                'patch': 'partial_update',
                'delete': 'destroy'
            },
            name='{basename}-detail',
            initkwargs={'suffix': 'Instance'}
        ),
    ]

# Routers provide an easy way of automatically determining the URL conf
router = HeadRouter()
#router.register(r'accounts', appviews.AccountViewSet)
#router.register(r'groups', appviews.GroupViewSet)
#router.register(r'verifications', appviews.VerificationViewSet)

router.register(r'app/nested_groups', appviews.NestedGroupViewSet,'nestedgroup')
router.register(r'app/lists/(?P<ulid>[-\w\d]+)', appviews.ListsViewSet,'list')
router.register(r'app/shares/(?P<share>[-\w\d]+)', appviews.ShareViewSet,'share')

router.register(r'user/mails', views.UserMailsViewSet,'mails')
#router.register(r'app/lists/(?P<list>[-\w\d]+)', views.ListViewSet,'list')

#format_suffix_patterns(
urlpatterns = [
    url(r'^user/auid/$', views.UserAUID.as_view(),name='auid'),
    url(r'^user/membership/$', views.UserMembership.as_view(),name='membership'),
    url(r'^user/profile/$', views.UserProfile.as_view(),name='profile'),
    url(r'^user/listmember/(?P<ulid>[-\w\d]+)/$', views.UserListMember.as_view(),name='listmember'),

    url(r'^session/membership/$', views.SessionMembership.as_view()),

    # SSL_BASIC_AUTH
    url(r'^backend/members/$', backendviews.MembersView.as_view(),name='members'),
    url(r'^backend/invitations/$', backendviews.InvitationsView.as_view(),name='invitations'),
    url(r'^backend/keys/$', backendviews.KeysView.as_view(),name='keys'),

    # SHARE_CLIENTS
    url(r'^app/shares/(?P<share>[-\w\d]+)/changes/$', appviews.ShareChangesView.as_view(),name='share-changes'),

    # LIST CLIENTS
    url(r'^app/lists/$', appviews.ListsView.as_view(),name='lists'),
]+router.urls

if getattr(settings, 'HAVE_ADMIN', False):
    from idapi import admin
    urlpatterns += [
        url(r'^exportlist/(?P<ulid>[-\w\d]+)/$', admin.export_list,name='export_list'),
    ]

#urlpatterns = format_suffix_patterns(urlpatterns)