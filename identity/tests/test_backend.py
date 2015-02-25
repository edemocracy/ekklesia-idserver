#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Backend unit tests
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

from tests.conftest import api, sender, receiver, basic_auth, tmp_json

@mark.parametrize("defect", [None])
#@mark.parametrize("defect", [None,'unknown','nokey','badcode','unverified'])
@mark.django_db
def test_registerkey(request,accounts,mails,bilateral,defect):
    from accounts.models import Account
    from idapi.models import Message, PublicKey
    from idapi.mails import gnupg_init, get_mails, send_mails, update_keyrings, process_register
    import email.mime.text
    from kryptomime import create_mail
    from kryptomime.pgp import find_gnupg_key
    import tempfile
    home = tempfile.mkdtemp()
    gpg = gnupg_init(home)
    update_keyrings(debug_gpg=gpg,debug_import=bilateral['gpg1'])

    user = accounts['member1']
    id1, id2 = bilateral['id1'], bilateral['id2']
    key1 = find_gnupg_key(bilateral['gpg1'],sender)
    key2 = find_gnupg_key(bilateral['gpg2'],receiver)
    server, imapsend, imaprecv = mails
    # id1=register, id2=member1

    if defect=='unknown':
        # unknown sender, should be rejected
        unknown = 'unknown@localhost'
        imapbad = server.add_account(unknown,keep=False)
        msg = create_mail(unknown,sender,'register','register')
    elif defect=='nokey':
        # known sender, but forget key/signing
        msg = create_mail(receiver,sender,'register','register')
    else:
        # known sender, return confirmation request
        attach = id2.pubkey_attachment(key2)
        msg = create_mail(receiver,sender,'register','register',attach=[attach])

    assert server.send(msg)
    assert len(imapsend)==1
    get_mails(joint=True,debug=server,debug_gpg=gpg,keep=False)
    process_register(debug_gpg=gpg)
    send_mails(joint=True,debug=server,debug_gpg=gpg)

    if defect=='unknown':
        assert len(imapbad)==1
        for mail, flags in imapbad:
            mail, verified, result = id2.decrypt(mail,strict=False)
            assert mail and result
            assert not result['encrypted'] and result['signed'] and result['fingerprints']==[key1]
            #print mail
            # assert key1 attached
        return

    return #FIXME
    assert len(imaprecv)==1
    msg = None
    for mail, flags in imaprecv:
        mail, verified, result = id2.decrypt(mail,strict=False)
        assert mail and result
        assert result['signed'] and result['fingerprints']==[key1]
        assert bool(result['encrypted']) == (defect!='nokey')
        #print mail
        msg = mail
        # assert key1 attached
    if defect=='nokey':
        return

    if defect=='badcode':
        reply = create_mail(receiver,sender,'confirmation','bad code')
    else:
        body = msg.get_payload()
        reply = '> '+'> '.join(body.splitlines(True))
        reply = create_mail(receiver,sender,'Re: '+mail['subject'],reply)
        reply = id2.encrypt(reply,sign=True)
    assert server.send(reply)
    assert len(imapsend)==1
    get_mails(joint=True,debug=server,debug_gpg=gpg,keep=False)
    process_register(debug_gpg=gpg)
    send_mails(joint=True,debug=server,debug_gpg=gpg)
    assert len(imaprecv)==1
    for mail, flags in imaprecv:
        mail, verified, result = id2.decrypt(mail,strict=False)
        assert mail and result
        assert result['encrypted'] and result['signed'] and result['fingerprints']==[key1]
        #print mail
        msg = mail
        # assert key1 attached

    if defect=='badcode':
        return

    if defect!='unverified':
        key = user.publickeys.get(active=True)
        key.trust=PublicKey.TRUSTED
        key.save()
    msg = create_mail(receiver,sender,'test','test')
    msg = id2.encrypt(msg,sign=True)
    assert server.send(reply)
    assert len(imapsend)==1
    get_mails(joint=True,debug=server,debug_gpg=gpg,keep=False)

    # check verified = CONFIRMED/TRUST/...
    # verifiyed key, receive
    return

@mark.parametrize("variant", ['','2fac']) # update
@mark.django_db
def test_member(request,accounts,invitations,bilateral,client,variant,settings):
    from idapi.backendviews import get_members, update_members
    from accounts.models import Account, NestedGroup, Invitation, EMailConfirmation
    from ekklesia.data import json_decrypt, json_encrypt
    from django.conf import settings
    import os, json

    twofactor = variant=='2fac'
    setattr(settings, 'TWO_FACTOR_SIGNUP',twofactor)

    Invitation.objects.create(code='inv6',secret='password6',uuid='uid6',status=Invitation.REGISTERING)
    Invitation.objects.create(code='inv7',secret='password7',uuid='uid7',status=Invitation.REGISTERING)
    Invitation.objects.create(code='inv8',secret='password8',uuid='uid8',status=Invitation.REGISTERING)
    member6 = Account.objects.create(username='member6',status=Account.NEWMEMBER,is_active=False,
        email='member6@localhost',uuid='uid6')
    member7 = Account.objects.create(username='member7',status=Account.NEWMEMBER,is_active=False,
        email='member7@localhost',uuid='uid7')
    member8 = Account.objects.create(username='member8',status=Account.NEWMEMBER,is_active=False,
        email='member8@localhost',uuid='uid8')
    conf8 = EMailConfirmation.objects.create(user=member8, confirmation_key='key8')

    activate = ['activate'] if twofactor else []

    response, members = api(client,'backend/members/?new=1',user='members')
    assert response.status_code == 200
    members, encrypted, signed, result = json_decrypt(members,bilateral['id2'])
    assert encrypted and signed
    data = [['uid6','password6'],['uid7','password7']]
    assert members == dict(fields=['uuid']+activate, version=[1, 0], format='member',
         data=data if twofactor else [v[:-1] for v in data])

    response, members = api(client,'backend/members/',user='members')
    assert response.status_code == 200
    #members = get_members(crypto=bilateral['id1'])
    members, encrypted, signed, result = json_decrypt(members,bilateral['id2'])
    assert encrypted and signed
    data = [['uid1',''],['uid2',''],['uid3','']]+data
    assert members == dict(fields=['uuid']+activate, version=[1, 0], format='member',
         data=data if twofactor else [v[:-1] for v in data])

    data = [['uid1','eligible',1,2,''],['uid2','member',1,5,''],['uid3','deleted',0,0,''],
            ['uid6','member',1,0,True],['uid7','deleted',0,0,False]]
    members = dict(fields=['uuid','status','verified','department']+activate,
         version=[1, 0], format='member',
    #    data=[['uid1',0,0,2],['uid2',1,1,3],['uid3',1,1,4]])
         data=data if twofactor else [v[:-1] for v in data])
    departments = dict(fields=('id','parent','name','depth'), version=[1, 0], format='department',
    #    data=[[1,None,'root',1],[2,1,'sub',2],[3,2,'subsub',4],[4,1,'sub2',2]])
         data=[[1,None,'r00t',1],[2,1,'s0b',2],[5,2,'s0bsub',3],[4,2,'s0bsub2',3]])
    members, result = json_encrypt(members,bilateral['id2'],encrypt=['foo@localhost'],sign=True)
    #data, encrypted, signed, result = json_decrypt(members,bilateral['id1'])
    departments, result = json_encrypt(departments,bilateral['id2'],encrypt=['foo@localhost'],sign=True)
    response, result = api(client,'backend/members/','post',user='members',
        data=dict(members=members,departments=departments))
    assert response.status_code == 200

    assert not NestedGroup.objects.filter(syncid=3).exists()
    root = NestedGroup.objects.get(syncid=1)
    assert root.name=='r00t' and root.parent==None and root.depth==1
    sub = NestedGroup.objects.get(syncid=2)
    assert sub.name=='s0b' and sub.parent==root and sub.depth==2
    ssub = NestedGroup.objects.get(syncid=5)
    assert ssub.name=='s0bsub' and ssub.parent==sub and ssub.depth==3
    ssub2 = NestedGroup.objects.get(syncid=4)
    assert ssub2.name=='s0bsub2' and ssub2.parent==sub and ssub2.depth==3
    indep = NestedGroup.objects.get(name='indep')
    assert indep.syncid is None and indep.depth==1

    m = Account.objects.get(uuid='uid3')
    assert m.status==Account.DELETED
    assert list(m.nested_groups.all())==[indep]
    m = Account.objects.get(uuid='uid1')
    assert m.status==Account.ELIGIBLE and m.verified
    assert list(m.nested_groups.all())==[sub]
    m = Account.objects.get(uuid='uid2')
    assert m.status==Account.MEMBER and m.verified
    assert set(m.nested_groups.all())==set([ssub,indep])
    m = Account.objects.get(uuid='uid6')
    assert m.status==Account.MEMBER and m.verified
    assert not m.nested_groups.count()
    inv = Invitation.objects.get(uuid='uid6')
    assert inv.status==Invitation.REGISTERED
    assert not Account.objects.filter(uuid='uid7').exists()
    m = Account.objects.get(uuid='uid8')
    assert m.status==Account.NEWMEMBER
    inv = Invitation.objects.get(uuid='uid8')
    assert inv.status==Invitation.REGISTERING

    response, members = api(client,'backend/members/',user='members')
    assert response.status_code == 200
    members, encrypted, signed, result = json_decrypt(members,bilateral['id2'])
    assert encrypted and signed
    data = [['uid1',''],['uid2',''],['uid6','']]
    if not twofactor: data = [v[:-1] for v in data]
    assert members == dict(fields=['uuid']+activate, version=[1, 0], format='member',
         data=data)

@mark.django_db
def test_invitation(request,accounts,bilateral,invitations,client):
    from idapi.backendviews import get_invitations, update_invitations
    from ekklesia.data import json_decrypt, json_encrypt
    import os

    response, invitations = api(client,'backend/invitations/?changed=1',user='invitations')
    assert response.status_code == 200
    invitations, encrypted, signed, result = json_decrypt(invitations,bilateral['id2'])
    assert encrypted and signed
    assert invitations == dict(fields=['uuid','status'], version=[1, 0], format='invitation',
         data=[['uid1','registered'],['uid5','failed']])

    response, invitations = api(client,'backend/invitations/',user='invitations')
    assert response.status_code == 200
    #invitations = get_invitations(crypto=bilateral['id1'])
    invitations, encrypted, signed, result = json_decrypt(invitations,bilateral['id2'])
    assert encrypted and signed
    assert invitations == dict(fields=['uuid','status'], version=[1, 0], format='invitation',
         data=[['uid1','registered'],['uid4','new'],['uid5','failed']])

    invitations = dict(fields=['uuid','status','code'], version=[1, 0], format='invitation',
         data=[['uid1','registered',''],['uid4','new','inv4b'],
         ['uid5','new','inv5b'],['uid6','new','inv6']])

    invitations, result = json_encrypt(invitations,bilateral['id2'],encrypt=['foo@localhost'],sign=True)
    response, result = api(client,'backend/invitations/','post',invitations,user='invitations')
    assert response.status_code == 200

    invitations = get_invitations(crypto=False)
    assert invitations == dict(fields=['uuid','status'], version=[1, 0], format='invitation',
        data=[['uid4', 'new'], ['uid5', 'new'], ['uid6', 'new']])
