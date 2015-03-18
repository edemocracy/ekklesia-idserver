#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# User unit and integration tests
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

from tests.conftest import api, sender, receiver, third

def compare_mail(a,b):
    assert a.is_multipart() == b.is_multipart()
    # todo headers
    if a.is_multipart():
        for i in range(len(a.get_payload())):
            ap = a.get_payload(i)
            bp = b.get_payload(i)
            assert ap.as_string() == bp.as_string()
    else:
        assert a.get_payload() == b.get_payload()

@mark.django_db
def test_mail(mails,bilateral):
    import email.mime.text
    from kryptomime import create_mail, protect_mail
    from kryptomime.pgp import find_gnupg_key
    server, imapsend, imaprecv = mails
    id1, id2 = bilateral['id1'], bilateral['id2']
    key1 = find_gnupg_key(bilateral['gpg1'],sender)
    key2 = find_gnupg_key(bilateral['gpg2'],receiver)
    assert not len(imapsend) and not len(imaprecv)
    attachment = email.mime.text.MIMEText('some\nattachment')
    msg = create_mail(sender,receiver,'subject','body\nmessage',attach=[attachment])
    #msg = protect_mail(msg,linesep='\r\n')

    enc,_ = id1.encrypt(msg,sign=True,inline=False)
    assert enc and id2.analyze(enc) == (True,None)
    assert server.send(enc)
    assert not len(imapsend) and len(imaprecv)==1
    for mail, flags in imaprecv:
        mail, verified, result = id2.decrypt(mail)
        assert mail and verified and result
        assert result['encrypted'] and result['signed'] and result['fingerprints']==[key1]
        compare_mail(msg,mail)
    assert not len(imapsend) and not len(imaprecv)

    msg = create_mail(receiver,sender,'subject','body\nmessage',attach=[attachment])
    msg = protect_mail(msg,linesep='\r\n')
    sgn,_ = id2.sign(msg,inline=True,verify=True)
    assert sgn and id1.analyze(sgn) == (False,True)

    dec, verified, result = id1.decrypt(sgn,strict=True)
    assert dec and verified and result
    assert not result['encrypted'] and result['signed'] and result['fingerprints']==[key2]
    compare_mail(msg,dec)

    assert server.send(sgn)
    assert len(imapsend)==1 and not len(imaprecv)

    for mail, flags in imapsend:
        mail = protect_mail(mail,linesep='\r\n')
        dec, verified, result = id1.decrypt(mail,strict=True)
        assert dec and verified and result
        assert not result['encrypted'] and result['signed'] and result['fingerprints']==[key2]
        compare_mail(msg,dec)
    assert not len(imapsend) and not len(imaprecv)

def do_send(attach,request,accounts,apps,tokens,mails,bilateral,client,settings,defect):
    from accounts.models import Account
    from idapi.models import Message, PublicKey
    from idapi.mails import send_mails, update_keyrings, send_mail
    from rest_framework.exceptions import ValidationError, PermissionDenied, MethodNotAllowed
    from kryptomime.pgp import find_gnupg_key
    from kryptomime.mail import mail_payload
    queue = settings.EMAIL_QUEUE
    user = accounts['member1']
    token = tokens['member1']
    app = apps['portal']
    #update_keyrings()
    id1, id2 = bilateral['id1'], bilateral['id2']
    key1, key2 = bilateral['fingerprints']
    gpg = bilateral['gpg1']
    livemail = request.config.getoption('livemail')
    if livemail: server = None
    else: server, imapsend, imaprecv = mails

    content = {'subject':'hallo1','body':u'foö'}
    data = {'identity':'portal','content':content,'keep':True}
    if attach:
        msg = {'content':u'bär','content-type':'text/plain'}
        mfile = {'content':'foo\r\nbar','filename':'some.txt'}
        data['parts'] = [msg, 'second', mfile]
    else: msg = data
    excpt, error, estatus = None, None, None
    if defect=='client':
        app = apps['debug']
        excpt, estatus = PermissionDenied, 403
    elif defect=='noid':
        del data['identity']
        excpt, error = ValidationError, 'identity_missing'
    elif defect=='badid':
        data['identity']='bad'
        excpt, error = ValidationError, 'identity_unknown'
    elif defect=='idperm':
        data['identity']='register'
        excpt, error = ValidationError, 'identity_not_permitted'
    elif defect=='nosend':
        data['identity']='voting'
        excpt, estatus = MethodNotAllowed, 405
    elif defect=='notemplate':
        app = apps['voting']
        data['identity']='voting'
        excpt, error = ValidationError, 'template_not_permitted'
    elif defect=='template':
        data['template']='bad'
        excpt, error = ValidationError, 'template_unknown'
    elif defect=='content':
        msg['content']=''
        excpt, error = ValidationError, 'content_missing'
    elif defect=='ctype':
        msg['content-type']='image'
        excpt, error = ValidationError, 'type_error'
    elif defect=='cparams':
        msg['content-params']='bad'
        excpt, error = ValidationError, 'type_error'
    elif defect=='charset':
        msg['content-charset']='latin1'
        if attach: msg['content']= u'fo😃'
        else: content['body']= u'fo😃'
        excpt, error = ValidationError, 'type_error'
    elif defect=='encoding':
        msg['content-encoding']='7bit'
        excpt, error = ValidationError, 'type_error'
    elif defect=='sign':
        import copy # only top-level items are preserved
        settings.EMAIL_IDS = copy.deepcopy(settings.EMAIL_IDS)
        del settings.EMAIL_IDS['portal']['key']
        excpt, error = ValidationError, 'signing'

    if defect=='encrypt':
        excpt, error = ValidationError, 'pubkey_missing'
    else:
        user.publickeys.create(active=True,keytype=PublicKey.PGP,trust=PublicKey.TRUSTED,fingerprint=key2)

    def sendit(subject,sign,encrypt):
        content['subject'] = subject
        data['sign'],data['encrypt'] = sign, encrypt
        if queue==True:
            response, out = api(client,'user/mails/','post',data,token=token)
            if not excpt:
                assert response.status_code == 200
            else:
                assert response.status_code == (estatus or 400)
                assert not error or out['error'] == error
        else:
            if not excpt:
                resp = send_mail(data, user, app, debug=server,debug_gpg=gpg)
                if queue=='crypto' and (sign or encrypt):
                    assert resp['status'] == 'queued'
                    response, out = api(client,'user/mails/%s/' % resp['msgid'],token=token)
                    assert response.status_code == 200 and out['status'] == 'sent'
                    assert out['encrypt'] == encrypt and out['sign'] == sign
                else:
                    assert resp == dict(status='sent')
            else:
                with raises(excpt) as excinfo:
                    resp = send_mail(data, user, app, debug=server,debug_gpg=gpg)
                assert not error or excinfo.value.detail['error'] == error

    sendit('hallo1',True,True)
    if excpt: return
    sendit('hallo2',False,False)
    sendit('hallo3',True,False)
    sendit('hallo4',False,True)
    if queue==True:
        send_mails(joint=True,debug=server,debug_gpg=gpg)
    if livemail:
        server.close()
        return
    assert not len(imapsend) and len(imaprecv)==4
    for mail, flags in imaprecv:
        mail, verified, result = id2.decrypt(mail)
        assert mail and result
        subj = mail['subject']
        if attach:
            assert mail_payload(mail)==[u'foö',u'bär',u'second',u'foo\r\nbar']
        else:
            assert mail_payload(mail)==content['body']
        assert result['encrypted']==(subj in ('hallo1','hallo4'))
        assert result['signed']==(subj in ('hallo1','hallo3'))
        if result['signed']: assert result['fingerprints']==[key1]

mail_defects = ['','noid','id','idperm','nosend','template','sign','encrypt',
    'content','ctype','cparams','charset','encoding']

@mark.parametrize("defect", mail_defects+['client'])
@mark.django_db
def test_send_direct(request,accounts,apps,tokens,mails,bilateral,client,settings,defect):
    settings.EMAIL_QUEUE = False
    do_send(False, request,accounts,apps,tokens,mails,bilateral,client,settings,defect)

@mark.django_db
def test_send_mixed(request,accounts,apps,tokens,mails,bilateral,client,settings):
    settings.EMAIL_QUEUE = 'crypto'
    settings.BROKER_URL = 'dummy'
    do_send(False, request,accounts,apps,tokens,mails,bilateral,client,settings,'')

@mark.parametrize("defect", ['','content','ctype','cparams','charset','encoding'])
@mark.django_db
def test_send_attach(request,accounts,apps,tokens,mails,bilateral,client,settings,defect):
    settings.EMAIL_QUEUE = False
    do_send(True, request,accounts,apps,tokens,mails,bilateral,client,settings,defect)

@mark.parametrize("defect", mail_defects)
@mark.django_db
def test_send_queue(request,accounts,apps,tokens,mails,bilateral,client,settings,defect):
    settings.EMAIL_QUEUE = True
    do_send(False, request,accounts,apps,tokens,mails,bilateral,client,settings,defect)

@mark.parametrize("defect", [None])
@mark.django_db
def test_receive(request,accounts,tokens,mails,bilateral,client,defect):
    from accounts.models import Account
    from idapi.models import Message, PublicKey
    from idapi.mails import get_mails, update_keyrings
    import email.mime.text, six
    from kryptomime import create_mail, protect_mail
    from kryptomime.pgp import find_gnupg_key

    user = accounts['member1']
    token = tokens['member1']
    #update_keyrings()
    id1, id2 = bilateral['id1'], bilateral['id2']
    key1 = find_gnupg_key(bilateral['gpg1'],sender)
    key2 = find_gnupg_key(bilateral['gpg2'],receiver)
    livemail = request.config.getoption('livemail')
    if livemail: server = mails
    else: server, imapsend, imaprecv = mails
    if not livemail: assert not len(imapsend) and not len(imaprecv)

    user.publickeys.create(active=True,keytype=PublicKey.PGP,trust=PublicKey.TRUSTED)

    key1 = find_gnupg_key(bilateral['gpg1'],sender)
    key2 = find_gnupg_key(bilateral['gpg2'],receiver)
    attachment = email.mime.text.MIMEText('some\nattachment')
    msg = create_mail(receiver,sender,'subject','body\nmessage',attach=[attachment])
    msg = protect_mail(msg,linesep='\r\n')

    assert server.send(msg)
    if not livemail: assert len(imapsend)==1 and not len(imaprecv)

    sgn,_ = id2.sign(msg,inline=True,verify=True)
    assert sgn and id1.analyze(sgn) == (False,True)
    assert server.send(sgn)
    if not livemail: assert len(imapsend)==2 and not len(imaprecv)

    enc,_ = id2.encrypt(msg,sign=True,inline=False)
    assert enc and id1.analyze(enc) == (True,None)
    assert server.send(enc)
    if not livemail: assert len(imapsend)==3 and not len(imaprecv)

    """
    for mail, flags in imapsend:
        mtype = id1.analyze(mail)
        if mtype != (False,False):
            if mtype == (False,True):
                verified, result = id1.verify(mail)
                mail = id1.strip_signature(mail)[0]
                mail = protect_mail(mail,linesep='\r\n')
            else: #if mtype == (True,None):
                mail, verified, result = id1.decrypt(mail)
            assert mail and verified and result
            assert result['signed'] and result['fingerprints']==[key2]
            assert result['encrypted']==(mtype != (False,True))
        else: mail = protect_mail(mail,linesep='\r\n')
        compare_mail(msg,mail)
    assert not len(imapsend) and not len(imaprecv)
    """
    get_mails(joint=True,debug=None if livemail else server,debug_gpg=bilateral['gpg1'],keep=False)
    if not livemail: assert not len(imapsend) and not len(imaprecv)

    response, out = api(client,'user/mails/',token=token)
    assert response.status_code == 200
    todo = [(False,False),(True,False),(True,True)]
    for mid in out['items']:
        response, out = api(client,'user/mails/%i/'% mid,token=token)
        assert response.status_code == 200
        parts = out['parts']
        assert out['subject']=='subject' and len(parts)==2
        signed, encrypted = out['signed'],out['encrypted']
        contents = ['body\r\nmessage','some\r\nattachment']
        assert parts[0]=={'content': contents[0], 'content-charset': 'us-ascii', 'content-type': 'text/plain', 'content-encoding': '7bit'}
        assert parts[1]=={'content': contents[1], 'content-charset': 'us-ascii', 'content-type': 'text/plain', 'content-encoding': '7bit'}
        todo.remove((signed,encrypted))
        if signed: assert out['verified']=='trusted'
        #print out
    assert not todo

    if livemail: server.close()

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
