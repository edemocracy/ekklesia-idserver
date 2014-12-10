# -*- coding: utf-8 -*-
#
# DB unit tests
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
from pytest import fixture

from ekklesia.tests.conftest import sender, receiver, third, keys, gpgsender, gpgreceiver, bilateral

def pytest_addoption(parser):
    import ekklesia.tests.conftest
    ekklesia.tests.conftest.pytest_addoption(parser)
    parser.addoption("--livemail", action="store_true", help="use live mail servers")

def tmp_json(data):
    "dump data to json tmpfile and return. tmp.name must be unliked after use"
    import json, tempfile
    tmp = tempfile.NamedTemporaryFile(delete=False)
    json.dump(data,tmp)
    tmp.seek(0)
    return tmp

@fixture(scope='session')
def ngroups(db):
    from accounts.models import NestedGroup
    root = NestedGroup.objects.create(syncid=1,name='root',depth=1,description='root')
    sub = NestedGroup.objects.create(syncid=2,name='sub',depth=2,parent=root)
    subsub = NestedGroup.objects.create(syncid=3,name='subsub',parent=sub,depth=4)
    sub2 = NestedGroup.objects.create(syncid=4,name='sub2',parent=root,depth=2)
    indep = NestedGroup.objects.create(syncid=None,name='indep',depth=1)
    return dict(root=root,sub=sub,subsub=subsub,sub2=sub2,indep=indep)

def create_user(username,password,cls=None,nested_groups=[],**kwargs):
    from accounts.models import Account
    if cls is None: cls = Account
    user = cls(username=username,**kwargs)
    user.set_password(password)
    user.save()
    if nested_groups:
        through = user.nested_groups.through
        through.objects.bulk_create((through(nestedgroup_id=ngroup.pk,account_id=user.pk) for ngroup in nested_groups))
    return user

@fixture(scope='session')
def accounts(db,ngroups):
    from accounts.models import Account, Guest, Verifier
    admin = create_user('admin','admin',is_staff=True,status=Account.SYSTEM)
    member1 = create_user('member1','member1',status=Account.MEMBER,nested_groups=[ngroups['sub']],
        email=receiver,uuid='uid1',verified=False)
    member2 = create_user('member2','member2',status=Account.ELIGIBLE,
        nested_groups=[ngroups['subsub'],ngroups['indep']],
        email=third,uuid='uid2',verified=True)
    verify = create_user('verify','verify',cls=Verifier,status=Account.ELIGIBLE,
        nested_groups=[ngroups['sub2'],ngroups['indep']],
        email='verify@localhost',uuid='uid3',verified=True,
        for_nested_groups=ngroups['root'],
        )
    guest = create_user('guest','guest',cls=Guest,status=Account.GUEST,email='guest@localhost',
        first_name='Friendly',last_name='Foe',address='Milky Way',city='Atlantis',postal_code=1234,country='XX')
    return dict(admin=admin,member1=member1,member2=member2,verify=verify,guest=guest)

@fixture(scope='session')
def invitations(db):
    from accounts.models import Invitation
    Invitation.objects.create(code='inv1',uuid='uid1',status=Invitation.REGISTERED)
    Invitation.objects.create(code='inv4',uuid='uid4')
    Invitation.objects.create(code='inv5',uuid='uid5',status=Invitation.FAILED)

@fixture(scope='session')
def apps(db,accounts):
    from idapi.models import IDApplication
    portal = IDApplication.objects.create(name='portal',client_id='portal',client_secret='secret',user=accounts['admin'],
        redirect_uris="https://localhost/accounts/auth", client_type=IDApplication.CLIENT_CONFIDENTIAL, 
        authorization_grant_type=IDApplication.GRANT_AUTHORIZATION_CODE,
        permitted_scopes='unique member profile mail',
        required_scopes='unique member',autopermit_scopes='unique member',
        push_uris='',push_secret='', two_factor_auth=False,
    )
    debug = IDApplication.objects.create(name='debug',client_id='debug',client_secret='debug',user=accounts['admin'],
        redirect_uris='', client_type=IDApplication.CLIENT_CONFIDENTIAL, 
        authorization_grant_type=IDApplication.GRANT_PASSWORD,
        permitted_scopes='unique member profile mail',
        required_scopes='unique member',
        push_uris='',push_secret='', two_factor_auth=False,
    )
    return dict(portal=portal,debug=debug)

@fixture(scope='session')
def tokens(db,accounts,apps):
    from oauth2_provider.models import Grant, AccessToken
    from django.utils import timezone
    import datetime
    token = AccessToken.objects.create(user=accounts['member1'], token='1234567890',
                              application=apps['portal'],scope='unique member profile mail',
                              expires=timezone.now()+datetime.timedelta(days=1))
    return dict(member1=token.token)

def basic_auth(user,password):
    import base64
    token = user+':'+password
    token = base64.b64encode(token.encode('ascii'))
    return {'HTTP_AUTHORIZATION': 'Basic ' + token.decode('ascii')}

def api(client,url,method='get',data=None,app=None,user=None,token=None,multipart=False):
    import json
    kwargs = {'X-SSL-Verified':'SUCCESS','X-SSL-Client-Cert':'FAKE CERT','wsgi.url_scheme': 'https'}
    if app: kwargs.update(basic_auth(app.client_id,app.client_secret))
    elif user: kwargs.update(basic_auth(user,user))
    elif token: kwargs.update({'HTTP_AUTHORIZATION':'Bearer '+token})
    if not data is None:
        if multipart or method=='get': kwargs['data']=data
        else:
            kwargs['data'] = json.dumps(data)
            kwargs['content_type']='application/json'
    response = getattr(client,method)('/api/v1/'+url, secure=True, **kwargs)
    resp = response.content.decode('utf-8')
    out = json.loads(resp) if response['content-type']=='application/json' and resp else None
    return response, out

@fixture(scope='session')
def mails(request):
    if request.config.getoption('livemail'):
        from django.conf import settings
        from ekklesia.mail import SMTPConfig, smtp_init
        defaults = getattr(settings, 'EMAIL_DEFAULT_SMTP', None)
        if not defaults: return
        config = {}
        if defaults: config.update(defaults)
        user = getattr(settings, 'EMAIL_HOST_USER', None)
        if user:
            config['user'] = user
            config['password'] = settings.EMAIL_HOST_PASSWORD
        return smtp_init(config)
    from ekklesia.mail import VirtualMailServer
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    server = VirtualMailServer(tmpdir)
    imapsend = server.add_account(sender,keep=False)
    imaprecv = server.add_account(receiver,keep=False)
    def fin():
        server.finish()
        shutil.rmtree(tmpdir,ignore_errors=True)
    request.addfinalizer(fin)
    return server, imapsend, imaprecv
