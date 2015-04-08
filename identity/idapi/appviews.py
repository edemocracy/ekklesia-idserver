# -*- coding: utf-8 -*-
#
# Application views
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

from django.contrib.auth.models import Group

from oauth2_provider.ext.rest_framework import TokenHasScope

from idapi.serializers import GroupSerializer, NestedGroupSerializer, AccountSerializer, UserListSerializer, VerificationSerializer
from accounts.models import NestedGroup, Verification
from idapi.models import Share, ShareObject, UserList, UserListMember, get_auid
from django.conf import settings

from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet
from rest_framework.response import Response
from rest_framework import status, permissions, viewsets
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework import exceptions
from idapi.authentication import SSLClientAuthentication

from django.utils.decorators import method_decorator
from idapi.decorators import condition

def modified_list(request, share, **kwargs):
    return request.share.last_modified

def etag_list(request, share, **kwargs):
    return str(request.share.version)

def modified_detail(request, share, pk, **kwargs):
    if request.share_obj is None: return None
    return request.share_obj.last_modified

def etag_detail(request, share, pk, **kwargs):
    if request.share_obj is None: return None
    return str(request.share_obj.version)

class ShareViewSet(ViewSet):
    authentication_classes = (SSLClientAuthentication,)
    permission_classes = ()
    parser_classes = (JSONParser, FormParser, MultiPartParser)

    def initial(self, request, share, *args, **kwargs):
        super(ShareViewSet,self).initial(request, *args, **kwargs)
        shares = settings.SHARE_CLIENTS
        try: clients = shares[share]
        except KeyError: raise exceptions.PermissionDenied('Share does not exist.')
        except: raise exceptions.PermissionDenied()
        try: verbs = clients[request.auth.client_id]
        except: raise exceptions.PermissionDenied()
        if not request.method.lower() in verbs:
            self.http_method_not_allowed(request, *args, **kwargs)
        share = get_object_or_404(Share,name=share)
        request.share = share
        if not 'pk' in kwargs: return
        try:
            pk = int(kwargs['pk'])
            request.share_obj = share.objs.filter(no=pk).first()
            if share.ref_counting and share.share_changes.filter(no=pk,
                client=request.auth, action=ShareAction.SEEN).exists():
                request.share_obj = None # already deleted for client
        except ValueError:
            request.share_obj = None

    @method_decorator(condition(etag_func=etag_list, last_modified_func=modified_list))
    def list(self, request, share, format=None):
        if request.method == 'HEAD': return Response()
        def getisotime(param):
            x = request.GET.get(param)
            if x: x = datetime.datetime(*time.strptime(x,"%Y%m%dT%H%M%SZ")[0:6])
            return x
        def getint(param):
            x = request.GET.get(param)
            try: return int(x)
            except: return None
        share = request.share
        query = share.objs
        before, after = getisotime('before'), getisotime('after')
        first, last = getint('first'), getint('last')
        start, stop = getint('start'), getint('stop')
        count = getint('count')
        if before: query = query.filter(last_modified__lt=before)
        if after: query = query.filter(last_modified__gt=after)
        if first: query = query.filter(version__gte=first)
        if not last is None: query = query.filter(version__lte=last)
        if start: query = query.filter(no__gte=start)
        if not stop is None: query = query.filter(no__lte=stop)
        query = query.order_by('no').all()
        if count and not share.ref_counting: query = query[:count]
        objs = []
        for obj in query:
            if not count is None and len(objs) >= count: break
            if share.ref_counting and share.share_changes.filter(no=obj.no, 
                client=request.auth, action=ShareChange.SEEN).exists():
                continue # already deleted for client
            uri = reverse('v1:share-detail',kwargs={'share':share.name,'pk':obj.no})
            uri = request.build_absolute_uri(uri)
            size = len(str(obj.data))
            objs.append({'no':obj.no,'uri':uri,'size':size,
                'version':obj.version,'last_modified':obj.last_modified})
        return Response({'name':share.name,'maxid':share.maxno,'total':share.objs.count(),
                'nobjects':len(objs),'objects':objs})

    @method_decorator(condition(etag_func=etag_list, last_modified_func=modified_list,update=()))
    def create(self, request, share, format=None):
        from django.utils.http import http_date, quote_etag
        from calendar import timegm
        obj = ShareObject(share=request.share,data=request.data,last_client=request.auth)
        obj.save()
        location = request.build_absolute_uri(reverse('v1:share-detail',kwargs={'share':share,'pk':obj.no}))
        headers = {'Location':location,'ETag':quote_etag(str(obj.version)),
            'Last-modified':http_date(timegm(obj.last_modified.utctimetuple()))}
        return Response(obj.data,headers=headers,status=status.HTTP_201_CREATED)

    @method_decorator(condition(etag_func=etag_detail, last_modified_func=modified_detail))
    def retrieve(self, request, share, pk, format=None):
        if request.share_obj is None: raise Http404
        if request.method == 'HEAD': return Response()
        return Response(request.share_obj.data)

    @method_decorator(condition(etag_func=etag_detail, last_modified_func=modified_detail))
    def update(self, request, share, pk, format=None):
        if request.share_obj is None:
            return HttpResponse(status=403)
            """ RECREATING DELETED OBJECTS NOT ALLOWED
            try: pk = int(kwargs['pk'])
            except ValueError: return HttpResponse(status=403)
            if pk > request.share.maxno: return HttpResponse(status=403) # only allow deleted ids
            obj = ShareObject(share=request.share,data=request.data)
            status = status.HTTP_201_CREATED
            """
        else:
            obj = request.share_obj
            obj.data = request.data
            code = status.HTTP_200_OK
        obj.save(client = request.auth)
        return Response(obj.data,status=code)

    @method_decorator(condition(etag_func=etag_detail, last_modified_func=modified_detail))
    def partial_update(self, request, share, pk, format=None):
        from six import iteritems
        if request.share_obj is None: raise Http404
        obj = request.share_obj
        for k,v in iteritems(request.data): obj.data[k] = v
        obj.save(client = request.auth)
        return Response(obj.data)

    @method_decorator(condition(etag_func=etag_detail, last_modified_func=modified_detail))
    def destroy(self, request, share, pk, format=None):
        obj = request.share_obj
        if obj is None: raise Http404
        obj.delete(client=request.auth)
        return Response(obj.data,status=status.HTTP_204_NO_CONTENT)

class ShareChangesView(APIView):
    authentication_classes = (SSLClientAuthentication,)
    permission_classes = ()
    parser_classes = (JSONParser, FormParser, MultiPartParser)

    def initial(self, request, share, *args, **kwargs):
        super(ShareChangesView,self).initial(request, *args, **kwargs)
        shares = settings.SHARE_CLIENTS
        try: clients = shares[share]
        except KeyError: raise exceptions.PermissionDenied('Share does not exist.')
        except: raise exceptions.PermissionDenied()
        try: verbs = clients[request.auth.client_id]
        except: raise exceptions.PermissionDenied()
        if not request.method.lower() in verbs:
            self.http_method_not_allowed(request, *args, **kwargs)
        #print request.auth.client_id,'trying', share
        share = get_object_or_404(Share,name=share)
        request.share = share

    def get(self, request, share, format=None):
        def getint(param,default=None):
            x = request.GET.get(param)
            if x:
                try: x = int(x)
                except ValueError: return default
            else: x = default
            return x
        changes = request.share.changes
        start = getint('last',0)
        all = getint('all',0)
        stop = getint('stop',request.share.version) # lock
        if start: changes = changes.filter(version__gt=start)
        changes = changes.filter(version__lte=stop)
        created,modified,deleted = set(),set(),set()
        changes = changes.order_by('version')
        first = 0
        for change in changes.all():
            if not first: first = change.version
            if change.action==ShareChange.CREATE:
                created.add(change.no)
            elif change.action==ShareChange.MODIFY:
                if all or not change.no in created:
                    modified.add(change.no)
            elif change.action==ShareChange.DELETE:
                if all:
                    deleted.add(change.no)
                    continue
                if change.no in created:
                    created.remove(change.no)
                if change.no in modified:
                    modified.remove(change.no)
                else:
                    deleted.add(change.no)
        def geturis(objs):
            return [request.build_absolute_uri(reverse('v1:share-detail',kwargs={'share':share,'pk':no})) for no in objs]
        data = {'share':share,'first':first,'last':stop,'current':request.share.version,
            'created':geturis(created),'modified':geturis(modified),'deleted':geturis(deleted)}
        return Response(data)

#--------------------------------------------------------------------------

def modified_ulist(request, ulid, **kwargs):
    return request.ulist.last_modified

def etag_ulist(request, ulid, **kwargs):
    return str(request.ulist.version)

class ListsView(APIView):
    authentication_classes = (SSLClientAuthentication,)
    permission_classes = ()
    parser_classes = (JSONParser,)

    def initial(self, request, *args, **kwargs):
        super(ListsView,self).initial(request, *args, **kwargs)
        clients = settings.LISTS_CLIENTS
        try: verbs = clients[request.auth.client_id]
        except: raise exceptions.PermissionDenied()
        if not request.method.lower() in verbs:
            self.http_method_not_allowed(request, *args, **kwargs)

    def post(self, request, format=None):
        from django.utils.http import http_date, quote_etag
        from calendar import timegm
        from idapi.models import ApplicationUUID
        data = request.data
        if not 'users' in data: raise Http404
        users = []
        for auid in data['users']:
            if auid:
                user = get_object_or_404(ApplicationUUID,uuid=auid,application=request.auth).user
            else:
                user = None
            users.append(user)
        listdata = {}
        for field in ('name','info'):
            if not field in data: continue
            listdata[field] = data[field]
        ulist = UserList.objects.create(owner=request.auth,**listdata)
        for i, user in enumerate(users):
            if user:
                obj = UserListMember.objects.create(userlist=ulist,member=user)
                assert obj.no == i+1
            else:
                ulist.skip_object()
        from idapi.models import notify_list
        notify_list(ulist.ulid,'create')
        return Response({'ulid':ulist.ulid},status=status.HTTP_201_CREATED)

class ListsViewSet(ViewSet):
    authentication_classes = (SSLClientAuthentication,)
    permission_classes = ()
    parser_classes = (JSONParser,)

    def initial(self, request, ulid, *args, **kwargs):
        super(ListsViewSet,self).initial(request, *args, **kwargs)
        clients = settings.LISTS_CLIENTS
        #try: clients = shares[share]
        #except KeyError: raise exceptions.PermissionDenied('Share does not exist.')
        #except: raise exceptions.PermissionDenied()
        try: verbs = clients[request.auth.client_id]
        except: raise exceptions.PermissionDenied()
        if not request.method.lower() in verbs:
            self.http_method_not_allowed(request, *args, **kwargs)
        #print request.auth.client_id,'trying', share
        ulist = get_object_or_404(UserList,ulid=ulid)
        request.ulist = ulist
        if not 'pk' in kwargs: return
        try:
            pk = int(kwargs['pk'])
            request.ulistmember = ulist.objs.filter(no=pk).first()
        except ValueError:
            request.ulistmember = None

    #@method_decorator(condition(etag_func=etag_list, last_modified_func=modified_list))
    def list(self, request, ulid, format=None):
        if request.method == 'HEAD': return Response()
        ulist = request.ulist
        query = ulist.members.order_by('no').all()
        users = []
        last = 1
        for user in query:
            while last < user.no:
                users.append('') # fill up empty
                last += 1
            auid = get_auid(request.auth,user.member)
            users.append(auid.uuid)
            last += 1
        return Response({'name':ulist.name,'info':ulist.info,'maxid':ulist.maxno,'total':ulist.members.count(),
                'nusers':len(users),'users':users})

    def destroy(self, request, ulid, pos, format=None):
        member = request.ulistmember
        if member is None: raise Http404
        member.delete(client=request.auth)
        auid = get_auid(request,member).uuid
        notify_list(request.ulist.ulid,'modify')
        return Response({'auid':auid,'position':pos},status=status.HTTP_204_NO_CONTENT)

class ListsMemberView(APIView):
    authentication_classes = (SSLClientAuthentication,)
    permission_classes = ()
    parser_classes = (JSONParser, FormParser, MultiPartParser)

    def get(self, request, ulid, pos, format=None):
        from models import UserList
        return Response()

#--------------------------------------------------------------------------

class AccountViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    permission_classes = [permissions.IsAdminUser]
    queryset = User.objects.all()
    serializer_class = AccountSerializer

class VerificationViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    permission_classes = [permissions.IsAdminUser]
    queryset = Verification.objects.all()
    serializer_class = VerificationSerializer

class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    permission_classes = [permissions.IsAdminUser]
    queryset = Group.objects.all()
    serializer_class = GroupSerializer

class NestedGroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    #authentication_classes = (SSLClientAuthentication,)
    permission_classes = [permissions.AllowAny]
    #permission_classes = [permissions.IsAuthenticated]
    queryset = NestedGroup.objects.all()
    serializer_class = NestedGroupSerializer
