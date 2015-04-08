# -*- coding: utf-8 -*-
#
# Views
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

from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
User = get_user_model()
from django.core.urlresolvers import reverse

from oauth2_provider.ext.rest_framework import TokenHasScope, OAuth2Authentication

from idapi.models import UserList, PublicKey
from django.conf import settings

from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet
from rest_framework.response import Response
from rest_framework import status, permissions, viewsets
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework import exceptions
from rest_framework.authentication import SessionAuthentication

class UserAUID(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [TokenHasScope]
    required_scopes = ['unique']

    def get(self, request, format=None):
        from idapi.models import get_auid
        token = request.auth
        user = token.user
        auid = get_auid(token.application,user)
        return Response({'auid':auid.uuid})

def get_user_info(user):
    from accounts.models import Account
    ngroups = [ngroup.pk for ngroup in user.nested_groups.all()]
    allngroups = set([g.pk for g in user.get_nested_groups(parents=True)])
    status = dict(Account.STATUS_CHOICES)[user.status]
    verified = user.is_identity_verified()
    return {'type': status,'verified':verified,'nested_groups':ngroups,'all_nested_groups':allngroups}

class SessionMembership(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        return Response(get_user_info(request.user))

    def post(self, request, format=None):
        return self.get(request,format)

class UserMembership(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [TokenHasScope]
    required_scopes = ['member']

    def get(self, request, format=None):
        return Response(get_user_info(request.auth.user))

class UserListMember(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [TokenHasScope]
    required_scopes = ['member']

    def get(self, request, ulid, format=None):
        from idapi.models import UserList
        user = request.auth.user
        list = get_object_or_404(UserList,ulid=ulid)
        data = {'ismember':list.is_member(user),'listID':ulid}
        return Response(data)

class UserProfile(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [TokenHasScope]
    required_scopes = ['profile']

    def get(self, request, format=None):
        user = request.user
        data = {'username':user.username}
        public_id = user.get_verified_public_id()
        if public_id: data['public_id'] = public_id
        profile = user.get_verified_profile()
        if profile: data['profile'] = profile
        data['avatar'] = bool(user.avatar)
        return Response(data)

class UserMailsViewSet(ViewSet):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [TokenHasScope]
    required_scopes = ['mail']
    parser_classes = (JSONParser,)

    def list(self, request, format=None):
        from idapi.models import Message
        app = request.auth.application
        identities = self.allowed_identities(app)

        incoming = request.GET.get('in',True)
        outgoing = request.GET.get('out',False)
        # hide encrypted mails
        msgs = Message.objects.filter(user=request.user,email=True,crypto=False,identity__in=identities)
        if incoming and not outgoing: msgs = msgs.filter(outgoing=False)
        elif not incoming and outgoing: msgs = msgs.filter(outgoing=True)
        elif not (incoming or outgoing): return Response({})
        return Response({'items':[msg.pk for msg in msgs.all()]})

    def create(self, request, format=None):
        from idapi.mails import send_mail
        return Response(send_mail(request.data,request.user,request.auth.application))

    def allowed_identities(self, app):
        import six
        from rest_framework.exceptions import ValidationError, MethodNotAllowed
        clients = settings.EMAIL_CLIENTS
        try: allowed = clients[app.client_id]
        except KeyError:
            raise PermissionDenied(dict(error='client_not_permitted',
                details='client does not have permission to use the email interface'))
        return [id for id,v in six.iteritems(allowed) if v[0]]

    def check_access(self, app, user, pk):
        from idapi.models import Message
        from rest_framework.exceptions import PermissionDenied
        identities = self.allowed_identities(app)
        msg = get_object_or_404(Message,id=pk)
        if msg.user != user or not msg.identity in identities or \
            (msg.application and msg.application != app) or not msg.email: # or msg.crypto
            raise PermissionDenied()
        return msg

    def retrieve(self, request, pk, format=None):
        from ekklesia.data import isotime
        app = request.auth.application
        msg = self.check_access(app,request.user,pk)
        data = dict(msg.data)
        data['type'] = 'outgoing' if msg.outgoing else 'incoming'
        data['date'] = isotime(data['date'])
        data['processed'] = isotime(msg.time)
        data['status'] = dict(msg.STATUS_CHOICES)[msg.status]
        return Response(data)

    def destroy(self, request, pk, format=None):
        app = request.auth.application
        user = request.user
        msg = self.check_access(app,user,pk)
        msg.delete()
        return Response({},status=status.HTTP_204_NO_CONTENT)
