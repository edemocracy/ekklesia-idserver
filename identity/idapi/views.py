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

from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
User = get_user_model()
from django.core.urlresolvers import reverse

from oauth2_provider.ext.rest_framework import TokenHasScope, OAuth2Authentication

from idapi.models import UserList, Message, PublicKey
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

class SessionMembership(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        from accounts.models import Account
        user = request.user
        ngroups = [ngroup.id for ngroup in user.nested_groups.all()]
        allngroups = set([g.id for g in user.get_nested_groups(parents=True)])
        status = dict(Account.STATUS_CHOICES)[user.status]
        verified = user.is_identity_verified()
        data = {'type': status,'verified':verified,'nested_groups':ngroups,'all_nested_groups':allngroups}
        return Response(data)

    def post(self, request, format=None):
        return self.get(request,format)

class UserMembership(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [TokenHasScope]
    required_scopes = ['member']

    def get(self, request, format=None):
        from accounts.models import Account
        user = request.auth.user
        ngroups = [ngroup.id for ngroup in user.nested_groups.all()]
        allngroups = set([g.id for g in user.get_nested_groups(parents=True)])
        status = dict(Account.STATUS_CHOICES)[user.status]
        verified = user.is_identity_verified()
        data = {'type': status,'verified':verified,'nested_groups':ngroups,'all_nested_groups':allngroups}
        return Response(data)

class UserListMember(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [TokenHasScope]
    required_scopes = ['member']

    def get(self, request, ulid, format=None):
        from idapi.models import UserList
        user = request.auth.user
        list = get_object_or_404(UserList,ulid=ulid)
        #print list, list.__dict__
        data = {'ismember':list.is_member(user),'listID':ulid}
        #print(request.user,user,data)
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
        app = request.auth.application
        user = request.user
        identities = self.allowed_identities(app)
        if not identities: HttpResponse(status=403) # no permission

        incoming = request.GET.get('in',True)
        outgoing = request.GET.get('out',False)
        # hide encrypted mails
        msgs = Message.objects.filter(user=user,email=True,crypto=False,identity__in=identities)
        if incoming and not outgoing: msgs = msgs.filter(outgoing=False)
        elif not incoming and outgoing: msgs = msgs.filter(outgoing=True)
        elif not (incoming or outgoing): return Response({})
        return Response({'items':[msg.id for msg in msgs.all()]})

    def create(self, request, format=None):
        # FIXME error reports
        from time import time as epochtime
        from idapi.mails import create_mail
        from ekklesia.mail import Template
        user = request.user
        app = request.auth.application
        input = request.DATA
        msg = create_mail(input,app,user)
        if not msg:
            raise Http404
        else:
            return Response({'msgid':msg.pk})

    def allowed_identities(self, app):
        import six
        clients = getattr(settings, 'EMAIL_CLIENTS', {})
        try: allowed = clients[app.client_id]
        except: return None # no permission
        return [id for id,v in six.iteritems(allowed) if v[0]]

    def check_access(self, app, user, pk):
        identities = self.allowed_identities(app)
        if not identities: return None
        msg = get_object_or_404(Message,id=pk)
        if msg.user != user or not msg.identity in identities or \
            (msg.application and msg.application != app) or not msg.email or msg.crypto:
            return None # no permission
        return msg

    def retrieve(self, request, pk, format=None):
        app = request.auth.application
        user = request.user
        msg = self.check_access(app,user,pk)
        if not msg: return HttpResponse(status=403) # no permission
        data = {}
        data.update(msg.data)
        data['type'] = 'outgoing' if msg.outgoing else 'incoming'
        data['processed'] = msg.time
        return Response(msg.data)

    def destroy(self, request, pk, format=None):
        app = request.auth.application
        user = request.user
        msg = self.check_access(app,user,pk)
        if not msg: return HttpResponse(status=403) # no permission
        msg.delete()
        return Response({},status=status.HTTP_204_NO_CONTENT)
