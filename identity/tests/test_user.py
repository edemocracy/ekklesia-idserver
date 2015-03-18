#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# User unit and integration tests
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

from __future__ import absolute_import
from pytest import fixture, raises, mark

from tests.conftest import api, sender, receiver, third
from django.test import Client
from django.contrib.auth import SESSION_KEY

@mark.parametrize("ext", ['html','jade'])
@mark.django_db
def test_template(settings,ext):
    from accounts.views import template_location
    settings.DEBUG = ext == 'jade'
    assert template_location('form') == 'form.'+ext

class DummyContext(object):
    def __init__(self): pass
    def __enter__(self): pass
    def __exit__(self, et, ev, t): pass

def check_response(response,url=None,status=200,redirects=None,host='http://testserver'):
    if redirects is None:
        if url: redirects = 1
        else: redirects = 0
    assert len(response.redirect_chain)==redirects
    assert response.status_code == status
    if not redirects: return
    redir = response.redirect_chain[-1]
    assert redir[0] == host+url and redir[1]==302

@mark.parametrize("variant", ['','2fac','nocode','invitation_code','secret',
    'username','email','email2','noemail','password','nopassword','captcha','tos','confkey','expired'])
@mark.django_db
def test_register_member(accounts,invitations,variant,settings):
    from accounts.models import Account, Invitation, EMailConfirmation
    from django.core.urlresolvers import reverse
    from django.core import mail
    import os, re
    noop = DummyContext()
    if variant=='captcha' and not settings.RECAPTCHA_PRIVATE_KEY: return
    os.environ['RECAPTCHA_TESTING'] = 'True'
    twofactor = variant in ('2fac','secret')
    settings.TWO_FACTOR_SIGNUP = twofactor
    client = Client(secure=True)
    url = reverse('accounts:register')
    data = dict(code='inv4') if variant!='nocode' else {}
    response = client.get(url,data)
    assert response.status_code == 200
    form = response.context['form']
    data = form.initial
    if variant!='nocode': assert data['invitation_code'] == 'inv4'
    else: assert data['invitation_code'] is None

    secret = 'secret4' if twofactor else None
    data = dict(invitation_code='inv4', secret=secret, username='member4',
        email='member4@localhost',email2='member4@localhost',
        password='password4',password2='password4',tos=True,
        recaptcha_response_field='PASSED')
    if variant in ('invitation_code','secret','email2','password'): data[variant] = 'bad'
    elif variant=='username': data[variant] = 'member1' # exists
    elif variant=='email': data['email'] = data['email2']  = receiver # exists
    elif variant=='noemail': del data['email']
    elif variant=='nopassword': del data['password']
    elif variant=='captcha': data['recaptcha_response_field'] = 'FAIL'
    elif variant=='tos': data['tos'] = False
    response = client.post(url,data,follow=True)
    if variant in ['','2fac','nocode','secret','confkey','expired']: expect = noop
    else: expect = raises(AssertionError)
    with expect:
        check_response(response)
        assert 'form' not in response.context
        #assert 'Registration complete' in response.content
    if not expect is noop: return

    member4 = Account.objects.get(uuid='uid4',status=Account.NEWMEMBER,
        username='member4',email=None)
    assert member4.email_unconfirmed
    if variant=='secret': expect = raises(Invitation.DoesNotExist)
    else: expect = noop
    with expect:
        inv = Invitation.objects.get(uuid='uid4',status=Invitation.REGISTERING,secret=secret)
    if not expect is noop: return
    conf = member4.email_unconfirmed

    assert len(mail.outbox) == 1
    reply = mail.outbox[0]
    assert reply.to == ['member4@localhost']
    body = reply.body
    confurl = reverse('accounts:email_confirmation',kwargs=dict(confirmation_key='0'))
    confurl = confurl[:-2]+'(\w{40})/'
    confkey = re.search(confurl, body, re.IGNORECASE)
    assert conf.confirmation_key == confkey.group(1)
    if variant=='confkey':
        url = reverse('accounts:email_confirmation',kwargs=dict(confirmation_key=confkey.group(1)))
    else: url = confkey.group()
    if variant=='expired':
        import datetime
        conf.created -= datetime.timedelta(days=settings.EMAIL_CONFIRMATION_DAYS*2)
        conf.save()
    EMailConfirmation.objects.delete_expired()

    response = client.get(url,follow=True)
    check_response(response)

    if variant=='expired':
        assert not Account.objects.filter(uuid='uid4').exists()
        return
    member4 = Account.objects.get(uuid='uid4',status=Account.NEWMEMBER,
        username='member4',email='member4@localhost')
    with raises(AttributeError): member4.email_unconfirmed

def do_login(accounts,variant,settings,otp):
    from accounts.models import Account
    from django.core import mail
    from django.core.urlresolvers import reverse
    from django.http import QueryDict
    from django_otp.plugins.otp_email.models import EmailDevice
    import re
    member1 = accounts['member1']
    noop = DummyContext()
    client = Client(secure=True)
    device = 'django_otp.plugins.otp_email.models.EmailDevice/\d+'
    if variant=='inactive':
        member1.is_active = False
        member1.save(update_fields=['is_active'])
    elif variant in ['opton','optoff']:
        settings.TWO_FACTOR_AUTH = 'optional'
        member1.two_factor_auth = variant == 'opton'
        member1.save(update_fields=['two_factor_auth'])
    elif otp:
        settings.TWO_FACTOR_AUTH = 'mandatory'
    else:
        settings.TWO_FACTOR_AUTH = False
    if otp:
        EmailDevice.objects.create(user=member1, name='email', confirmed=True)
    url = reverse('accounts:index')
    if variant=='next':
        nexturl = reverse('accounts:profile')
        qd = QueryDict('', mutable=True)
        qd['next'] = nexturl
        url += '?' + qd.urlencode()
    else:
        nexturl = url
    if variant=='partial':
        assert client.login(username='member1',password='member1')
    response = client.get(url,follow=True)
    check_response(response)
    assert 'form' in response.context

    if variant!='partial':
        assert SESSION_KEY not in client.session
        data = dict(username='member1', password='member1')
        if variant in ('username','password'): data[variant] = 'bad'
        response = client.post(url,data,follow=True)
        if variant=='optoff':
            check_response(response,url)
            assert SESSION_KEY in client.session
            return
        if variant in ['','next','token','opton']: expect = noop
        else: expect = raises(AssertionError)
        with expect:
            if otp:
                assert SESSION_KEY not in client.session
                check_response(response)
                assert 'form' in response.context
                device = re.search(device, response.content.decode("utf8"))
                assert device
            else:
                check_response(response,nexturl)
                assert SESSION_KEY in client.session
                assert 'form' not in response.context
        if not otp or not expect is noop: return
    else:
        assert SESSION_KEY in client.session
        device = re.search(device, response.content.decode("utf8"))
        assert device
        data = {}

    data['otp_device'] = device.group()
    data['otp_challenge'] = "Get challenge"
    response = client.post(url,data,follow=True)
    check_response(response)
    assert variant=='partial' or SESSION_KEY not in client.session
    del data['otp_challenge']
    assert len(mail.outbox) == 1
    reply = mail.outbox[0]
    assert reply.to == [receiver]
    if variant=='token':
        expect = raises(AssertionError)
        data['otp_token'] = 'bad'
    else:
        expect = noop
        data['otp_token'] = reply.body
    with expect:
        response = client.post(url,data,follow=True)
        check_response(response,nexturl)
        assert SESSION_KEY in client.session
        assert 'form' not in response.context

@mark.parametrize("variant", ['','next','username','password','inactive'])
@mark.django_db
def test_login(accounts,variant,settings):
    do_login(accounts,variant,settings,otp=False)

@mark.parametrize("variant", ['','partial','next','username','password',
    'inactive','token','opton','optoff'])
@mark.django_db
def test_otplogin(db,accounts,variant,settings):
    do_login(accounts,variant,settings,otp=True)

def do_oauth(accounts,apps,variant,settings,otp):
    from accounts.models import Account
    from idapi.models import IDApplication
    from django.core.urlresolvers import reverse
    from django.http import QueryDict
    import json

    def check_redirect(response,redirect_uri):
        assert response.status_code == 302
        assert response.url.index(redirect_uri)==0
        from six.moves.urllib import parse
        params = QueryDict(parse.urlparse(response.url).query)
        assert params['state'] == 'mystate'
        return params

    noop = DummyContext()
    client = Client(secure=True)
    settings.TWO_FACTOR_AUTH = False
    member1 = accounts['member1']
    if variant=='inactive':
        member1.is_active = False
        member1.save(update_fields=['is_active'])

    url = reverse('authorize')
    app = apps['portal']
    qd = QueryDict('', mutable=True)
    redirect_uri = app.redirect_uris
    data = dict(
        redirect_uri = redirect_uri,
        client_id = app.client_id,
        scope = "unique member profile",
        state = "mystate",
        response_type = "code",
    )
    if variant in ('redirect_uri1','scope1','client_id1'):
        data[variant[:-1]] = 'bad'
        normal = False
    else: normal = True
    qd.update(data)
    url += '?' + qd.urlencode()
    response = client.get(url)
    assert SESSION_KEY not in client.session
    if not normal:
        if variant=='scope1':
            params = check_redirect(response,redirect_uri)
            assert params['error'] == 'invalid_scope'
        else: assert response.status_code == 400
        return
    else:
        assert response.status_code == 200
    data = response.context['form'].initial
    data.update(dict(username='member1', password='member1',allow='Authorize')) #,allow='Authorize'
    expect = raises(AssertionError)
    if variant in ('username','password'): data[variant] = 'bad'
    elif variant in ('redirect_uri2','scope2','client_id2'):
        data[variant[:-1]] = 'bad'
        if variant!='redirect_uri2': expect = noop
    elif variant=='inactive': pass
    else: expect = noop
    response = client.post(url,data,follow=False)
    with expect:
        params = check_redirect(response,redirect_uri)
        assert SESSION_KEY not in client.session
        if variant=='scope2':
            assert params['error']=='invalid_scope' and \
                params['error_description'] == 'scope bad is not permitted for this client'
            return
        elif variant=='client_id2':
            assert params['error']=='invalid_client_id'
            return
        code = params['code']
    if not expect is noop: return
    data = dict(
        code = code,
        client_id = app.client_id,
        client_secret = app.client_secret,
        grant_type = 'authorization_code',
        redirect_uri = redirect_uri,
    )
    expect = raises(AssertionError)
    if variant[:-1] in ('redirect_uri','client_id') and variant[-1]=='3':
        data[variant[:-1]] = 'bad'
    elif variant in ('client_secret','code'): data['client_secret'] = 'bad'
    else: expect = noop
    headers= {'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'}
    response = client.post(reverse('oauth2_provider:token'),data,**headers)
    with expect:
        assert response.status_code == 200
        resp = json.loads(response.content.decode('utf-8'))
        assert resp['scope'] == qd['scope'] and resp['token_type'] == 'Bearer'

@mark.parametrize("variant", ['','username','password','inactive',
    'redirect_uri1','scope1','client_id1', # fail during GET
    'redirect_uri2','scope2','client_id2', # fail during POST
    'redirect_uri3','client_id3','client_secret','code', # fail during token
])
@mark.django_db
def test_oauth(accounts,apps,variant,settings):
    do_oauth(accounts,apps,variant,settings,otp=False)

@mark.parametrize("variant", ['','logout','email','email2','inactive','password','uidb64','token'])
@mark.django_db
def test_password_reset(accounts,variant):
    from accounts.models import Account
    from django.core import mail
    from django.core.urlresolvers import reverse
    import re
    member1 = accounts['member1']
    noop = DummyContext()
    client = Client(secure=True)
    if variant=='inactive':
        member1.is_active = False
        member1.save(update_fields=['is_active'])
    elif variant=='logout':
        assert client.login(username='member1',password='member1')
        assert SESSION_KEY in client.session
    url = reverse('accounts:password_reset')
    response = client.get(url)
    assert response.status_code == 200
    assert SESSION_KEY not in client.session

    data = dict(email=member1.email)
    if variant=='email': data['email'] = 'bad@mail.com'
    elif variant=='email2': data['email'] = 'bad'
    response = client.post(url,data,follow=True)
    assert SESSION_KEY not in client.session
    check_response(response)
    if variant=='email2':
        assert 'form' in response.context
        return
    assert 'form' not in response.context

    if variant in ('email','inactive'):
        assert len(mail.outbox) == 0
        return
    assert len(mail.outbox) == 1
    reply = mail.outbox[0]
    assert reply.to == [receiver]
    body = reply.body
    confurl = reverse('accounts:password_reset_confirm',kwargs=dict(uidb64='000',token='1-2'))
    i = confurl.index('000')
    confurl = confurl[:i]+'([\w\-]+)/(\w{1,13}-\w{1,20})/'
    confkey = re.search(confurl, body, re.IGNORECASE)
    if variant in ('uidb64','token'):
        conf = dict(uidb64=confkey.group(1),token=confkey.group(2))
        conf[variant] = conf[variant][:-1]
        url = reverse('accounts:password_reset_confirm',kwargs=conf)
    else: url = confkey.group()

    response = client.get(url,follow=True)
    check_response(response)
    if variant in ('uidb64','token'):
        assert 'form' not in response.context
        return
    assert 'form' in response.context
    data = dict(new_password1='newpass',new_password2='newpass')
    if variant=='password': data['new_password1'] = 'bad'
    response = client.post(url,data,follow=True)
    check_response(response)
    if variant=='password':
        assert 'form' in response.context
        return
    assert 'form' not in response.context
    assert client.login(username='member1',password='newpass')

@mark.parametrize("variant", ['','username','password'])
@mark.django_db
def test_username_change(accounts,variant):
    from accounts.models import Account
    from django.core.urlresolvers import reverse
    member1 = accounts['member1']
    client = Client(secure=True)
    assert client.login(username='member1',password='member1')
    url = reverse('accounts:username')
    response = client.get(url)
    assert response.status_code == 200
    assert SESSION_KEY in client.session

    data = dict(username='xmember',password='member1')
    if variant=='username': data['username'] = 'member2'
    elif variant=='password': data['password'] = 'bad'
    response = client.post(url,data,follow=True)
    if variant:
        check_response(response)
        assert 'form' in response.context
        return
    check_response(response,reverse('accounts:index'))
    assert 'form' not in response.context
    assert Account.objects.get(username='xmember').pk == member1.pk
    client.logout()
    assert client.login(username='xmember',password='member1')

@mark.parametrize("variant", ['','keep','noemail','email','email2','password','expired'])
@mark.django_db
def test_email_change(accounts,variant):
    from accounts.models import Account, EMailConfirmation
    from django.core.urlresolvers import reverse
    from django.core import mail
    from django.conf import settings
    import re
    member1 = accounts['member1']
    client = Client(secure=True)
    assert client.login(username='member1',password='member1')
    url = reverse('accounts:email')
    response = client.get(url)
    assert response.status_code == 200
    assert SESSION_KEY in client.session

    data = dict(email='new@localhost',email2='new@localhost',password='member1')
    if variant=='email': data['email'] = 'bad@localhost'
    elif variant=='noemail': del data['email']
    elif variant=='email2': data['email'] = data['email2'] = third
    elif variant=='keep': data['email'] = data['email2'] = member1.email
    elif variant=='password': data['password'] = 'bad'
    response = client.post(url,data,follow=True)
    if variant not in ('','keep','expired'):
        check_response(response)
        assert 'form' in response.context
        return
    check_response(response,reverse('accounts:index'))
    assert 'form' not in response.context

    member1 = Account.objects.get(username='member1')
    if variant=='keep':
        assert member1.email == receiver
        with raises(AttributeError): member1.email_unconfirmed
        return

    conf = member1.email_unconfirmed

    assert len(mail.outbox) == 1
    reply = mail.outbox[0]
    assert reply.to == ['new@localhost']
    body = reply.body
    confurl = reverse('accounts:email_confirmation',kwargs=dict(confirmation_key='0'))
    confurl = confurl[:-2]+'(\w{40})/'
    confkey = re.search(confurl, body, re.IGNORECASE)
    assert conf.confirmation_key == confkey.group(1)
    url = confkey.group()
    if variant=='expired':
        import datetime
        conf.created -= datetime.timedelta(days=settings.EMAIL_CONFIRMATION_DAYS*2)
        conf.save()
    EMailConfirmation.objects.delete_expired()

    response = client.get(url,follow=True)
    check_response(response)

    if variant=='expired': email = member1.email
    else: email = 'new@localhost'
    member1 = Account.objects.get(username='member1',email=email)
    with raises(AttributeError): member1.email_unconfirmed

@mark.parametrize("variant", ['','old_password','new_password1'])
@mark.django_db
def test_password_change(accounts,variant):
    from accounts.models import Account
    from django.core.urlresolvers import reverse
    member1 = accounts['member1']
    client = Client(secure=True)
    assert client.login(username='member1',password='member1')
    url = reverse('accounts:password')
    response = client.get(url)
    assert response.status_code == 200
    assert SESSION_KEY in client.session

    data = dict(old_password='member1',new_password1='newpass',new_password2='newpass')
    if variant in ('old_password','new_password1'): data[variant] = 'bad'
    response = client.post(url,data,follow=True)
    if variant:
        check_response(response)
        assert 'form' in response.context
        return
    check_response(response,reverse('accounts:index'))
    assert 'form' not in response.context
    client.logout()
    assert client.login(username='member1',password='newpass')

@mark.django_db
def test_profile_change(accounts):
    from accounts.models import Account, Verification
    from django.core.urlresolvers import reverse
    member1, verifier = accounts['member1'], accounts['verify']
    client = Client(secure=True)
    assert client.login(username='member1',password='member1')
    url = reverse('accounts:profile_edit')
    response = client.get(url)
    assert response.status_code == 200
    assert SESSION_KEY in client.session
    data = response.context['form'].initial
    assert member1.get_verified_public_id() is None and \
        data['verified_public_id'] is None and data['public_id'] is None
    assert member1.get_verified_profile() is None and \
        data['verified_profile'] is None and data['profile'] is None
    Verification.objects.create(user=member1, verifier=verifier,
         public_id='public', profile='profile')
    url = reverse('accounts:profile_edit')
    response = client.get(url)
    assert response.status_code == 200
    assert SESSION_KEY in client.session
    data = response.context['form'].initial
    assert member1.get_verified_public_id()=='public' and \
        data['verified_public_id'] == 'public' and data['public_id']=='public'
    assert member1.get_verified_profile()=='profile' and \
        data['verified_profile'] == 'profile' and data['profile']=='profile'

    data = dict(public_id='public',profile='profile')
    response = client.post(url,data,follow=True)
    check_response(response,reverse('accounts:index'))
    assert 'form' not in response.context
    member1 = Account.objects.get(username='member1')
    assert member1.public_id is None and member1.profile is None

    data = dict(public_id='xpublic',profile='xprofile')
    response = client.post(url,data,follow=True)
    check_response(response,reverse('accounts:index'))
    assert 'form' not in response.context
    member1 = Account.objects.get(username='member1')
    assert member1.public_id== 'xpublic' and member1.profile=='xprofile'

@mark.django_db
def test_auid(apps,accounts,tokens,client):
    from idapi.models import get_auid
    from accounts.models import Account
    portal = apps['portal']
    debug = apps['debug']
    user = accounts['member1']
    auid = get_auid(portal,user).uuid
    token = tokens['member1']

    response, out = api(client,'user/auid/',token=token)
    assert response.status_code == 200 and out['auid']==auid

@mark.django_db
def test_session(apps,accounts,tokens,client):
    from idapi.models import get_auid
    from accounts.models import Account
    portal = apps['portal']
    debug = apps['debug']
    user = accounts['member1']
    token = tokens['member1']

    ngroups = [ngroup.id for ngroup in user.nested_groups.all()]
    allngroups = list(set([g.id for g in user.get_nested_groups(parents=True)]))
    status = dict(Account.STATUS_CHOICES)[user.status]
    verified = user.is_identity_verified()
    data = {'type': status,'verified':verified,'nested_groups':ngroups,'all_nested_groups':allngroups}

    response, out = api(client,'user/membership/')
    assert response.status_code == 401
    response, out = api(client,'user/membership/',token=token)
    assert response.status_code == 200 and out==data

    response, out = api(client,'session/membership/')
    assert response.status_code == 403
    assert client.login(username='member1', password='member1')
    response, out = api(client,'session/membership/')
    assert response.status_code == 200 and out==data
