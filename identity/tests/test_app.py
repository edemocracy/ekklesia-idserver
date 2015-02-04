#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# App unit tests
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
from pytest import fixture, raises, mark

from .conftest import api

@mark.django_db
def test_nested(ngroups,accounts):
    from accounts.models import NestedGroup
    root = NestedGroup.objects.get(name="root")
    sub = NestedGroup.objects.get(name="sub")
    assert root.depth==1
    assert sub.depth==2
    with raises(NestedGroup.DoesNotExist):
        sub = NestedGroup.objects.get(name="sub3")

@mark.django_db
def test_ngroups(apps,client):
    response, out = api(client,'app/nested_groups/')
    assert response.status_code == 200

def share_template(apps,client=None):
    from idapi.models import Share, ShareObject, ShareChange
    portal = apps['portal']
    debug = apps['debug']
    share = Share.objects.create(name="test",ref_counting=False)
    assert not share.objs.count()
    if client:
        response, out = api(client,'app/shares/test/',app=portal)
        assert response.status_code == 200
        assert out == dict(nobjects=0,total=0,maxid=0,name='test',objects=[])

    data1 = dict(foo='bar',number=3,check=True,sub=dict(a='b'),empty=None)
    data2 = dict(bar='foo',number=1)

    if client:
        response, out = api(client,'app/shares/test/','post',data1,app=portal)
        assert response.status_code == 201 and out == data1
        response, out = api(client,'app/shares/test/',app=portal)
        assert response.status_code == 200
        assert out['objects'][0]['no'] == 1
        del out['objects']
        assert out == dict(nobjects=1,total=1,maxid=1,name='test')
        response, out = api(client,'app/shares/test/1/',app=portal)
        assert response.status_code == 200 and out == data1
    else:
        obj1 = ShareObject.objects.create(share_id=share.pk,data=data1,last_client=portal)
    assert share.objs.count()==1
    tmp = share.objs.get(no=1)
    assert tmp.data==data1 and tmp.version==1
    share = Share.objects.get(name="test") 
    assert share.version==1 and share.maxno==1
    assert share.changes.count()==1
    tmp = share.changes.get(no=1)
    assert tmp.version==1 and tmp.action==ShareChange.CREATE and tmp.client==portal

    if client:
        response, out = api(client,'app/shares/test/','post',data2,app=debug)
        assert response.status_code == 201 and out == data2
        response, out = api(client,'app/shares/test/','get',dict(count=1),app=portal)
        assert response.status_code == 200
        assert out['objects'][0]['no'] == 1
        del out['objects']
        assert out == dict(nobjects=1,total=2,maxid=2,name='test')
        response, out = api(client,'app/shares/test/2/',app=portal)
        assert response.status_code == 200 and out == data2
    else:
        ShareObject.objects.create(share_id=share.pk,data=data2)
    assert share.objs.count()==2
    tmp = share.objs.get(no=2)
    assert tmp.data==data2 and tmp.version==2 #and tmp.share.version==2
    share = Share.objects.get(name="test")
    assert share.version==2 and share.maxno==2
    assert share.changes.count()==2
    tmp = share.changes.get(no=2)
    assert tmp.version==2 and tmp.action==ShareChange.CREATE
    if client: assert tmp.client==debug

    if client:
        response, out = api(client,'app/shares/test/1/','put',data2,app=debug)
        assert response.status_code == 200 and out == data2
        response, out = api(client,'app/shares/test/1/',app=portal)
        assert response.status_code == 200 and out == data2
    else:
        obj1.data = data2
        obj1.save(client=debug)
    assert share.objs.count()==2
    tmp = share.objs.get(no=1)
    assert tmp.data==data2 and tmp.version==3
    share = Share.objects.get(name="test")
    assert share.version==3 and share.maxno==2
    assert share.changes.count()==3
    tmp = share.changes.get(no=1,version=3)
    assert tmp.action==ShareChange.MODIFY and tmp.client==debug

    if client:
        response, out = api(client,'app/shares/test/1/','delete',app=portal)
        assert response.status_code == 204 and out is None
        response, out = api(client,'app/shares/test/1/',app=portal)
        assert response.status_code == 404 and out == dict(detail='Not found.')
    else:
        obj1.delete(client=portal)
    assert share.objs.count()==1
    with raises(ShareObject.DoesNotExist): share.objs.get(no=1)
    share = Share.objects.get(name="test") 
    assert share.version==4 and share.maxno==2
    assert share.changes.count()==4
    tmp = share.changes.get(no=1,version=4)
    assert tmp.action==ShareChange.DELETE and tmp.client==portal

@mark.django_db
def test_share_db(apps):
    share_template(apps)

@mark.django_db
def test_share_client(apps,client):
    share_template(apps,client)

def lists_template(apps,accounts,client=None):
    from idapi.models import UserList, UserListMember, get_auid
    portal = apps['portal']
    debug = apps['debug']
    users = accounts.values()
    auids = [get_auid(portal,user).uuid for user in users]

    info = dict(foo=3)
    if client:
        response, out = api(client,'app/lists/','post',dict(users=auids,name='test',info=info),app=portal)
        assert response.status_code == 201 and 'ulid' in out
        ulid = out['ulid']
        response, out = api(client,'app/lists/%s/'%ulid,app=portal)
        assert response.status_code == 200
        n = len(users)
        assert out == dict(name='test',info=info,users=auids,total=n,maxid=n,nusers=n)

        response, out = api(client,'app/lists/%s/'%ulid,app=debug)
        assert response.status_code == 200
        dauids = [get_auid(debug,user).uuid for user in users]
        assert out == dict(name='test',info=info,users=dauids,total=n,maxid=n,nusers=n)
    else:
        ulist = UserList.objects.create(name='test',info=info,owner=portal)
        for user in users:
            UserListMember.objects.create(userlist=ulist,member=user)

@mark.django_db
def test_lists_db(apps,accounts):
    lists_template(apps,accounts)

@mark.django_db
def test_lists_client(apps,accounts,client):
    lists_template(apps,accounts,client)
