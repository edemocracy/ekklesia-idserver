#!/usr/bin/env python
# coding: utf-8
#
# Tests
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

import os
from ekklesia.backends.invitations import InvitationDatabase, StatusType, SentStatusType, main_func
from pytest import fixture, raises, mark
from ekklesia.tests.conftest import sender, receiver, third, keys, gpgsender, gpgreceiver, bilateral, passphrase
import logging, json
from sqlalchemy import create_engine
from six.moves import cStringIO as StringIO

invitations = """invitation,1.0
uuid,email,code,status,sent
uid1,bar@localhost,inv1,registered,sent
uid5,inv5@localhost,inv5,failed,sent
uid6,inv6@localhost,inv6,uploaded,sent
uid7,inv7@localhost,inv7,uploaded,unsent
uid8,inv8@localhost,inv8,new,unsent
"""

def test_main():
    InvitationDatabase().run(['init'])

def gen_invitations(db,ids=False):
    i1 = db.Invitation(uuid='uid1',code='inv1',email=receiver,status='registered',sent='sent')
    i5 = db.Invitation(uuid='uid5',code='inv5',email='inv5@localhost',status='failed',sent='sent')
    i6 = db.Invitation(uuid='uid6',code='inv6',email='inv6@localhost',status='uploaded',sent='sent')
    i7 = db.Invitation(uuid='uid7',code='inv7',email='inv7@localhost',status='uploaded',sent='unsent')
    i8 = db.Invitation(uuid='uid8',code='inv8',email='inv8@localhost',status='new',sent='unsent')
    if ids: i1.id, i5.id, i6.id, i7.id, i8.id = 1,2,3,4,5
    return (i1,i5,i6,i7,i8)

def check_invs(db,invs=None):
    if not invs: invs = gen_invitations(db)
    session = db.session
    qinv = session.query(db.Invitation)
    assert len(invs) == qinv.count()
    for inv in invs:
        tinv = qinv.filter_by(uuid=inv.uuid,email=inv.email,status=inv.status,sent=inv.sent).one()
        #assert not inv.id or inv.id==tinv.id

def setup_db(configs):
    import logging
    db = InvitationDatabase(**configs)
    #db.setlogger('invitation','info')
    log = logging.getLogger('sqlalchemy')
    log.setLevel(logging.WARNING)
    #logging.captureWarnings(True)
    engine = create_engine(db.database,echo=db.debugging)
    db.open_db(engine,mode='create')
    return db

def_config = dict(invite_import=['uuid','email','code','status','sent'])

@fixture #(scope='session')
def empty_db(request,monkeypatch):
    db = setup_db(dict(config=def_config,gpgconfig=dict(sender=sender)))
    # Roll back at the end of every test
    request.addfinalizer(db.session.rollback)
    #request.addfinalizer(db.session.close)
    # Prevent the session from closing (make it a no-op) and
    # committing (redirect to flush() instead)
    monkeypatch.setattr(db.session, 'commit', db.session.flush)
    #monkeypatch.setattr(member_db.session, 'remove', lambda: None)
    return db

@fixture #(scope='session')
def inv_db(request, empty_db):
    db = empty_db
    invs = gen_invitations(db)
    db.session.add_all(invs)
    return db

def test_import(request,empty_db):
    db = empty_db
    db.import_invitations(StringIO(invitations))
    check_invs(db)

def test_import_change(request):
    imports = def_config['invite_import']
    cfg = dict(invite_import=imports+['lastchange'])
    db = setup_db(dict(config=cfg,gpgconfig=dict(sender=sender)))
    db.import_invitations(StringIO(invitations))
    check_invs(db)

def test_import_crypt(empty_db,bilateral):
    db = empty_db
    id2 = bilateral['id2']
    result = id2.encrypt_str(invitations,sender,sign=True)
    assert result.ok
    db.gpg = bilateral['id1']
    db.import_invitations(StringIO(str(result)),decrypt=True,verify=receiver)
    check_invs(db)

inv_dup = """invitation,1.0
uuid,email,code,status,sent
uid1,bar@localhost,inv1,registered,sent
uid1,foo@localhost,inv2,uploaded,sent
"""

def test_import_dup(empty_db):
    with raises(AssertionError):
        empty_db.import_invitations(StringIO(inv_dup))

def test_reimport(request,inv_db): #keys
    inv_db.import_invitations(StringIO(invitations))
    check_invs(inv_db)

inv_mail = """invitation,1.0
uuid,email,code,status,sent
uid1,bar@localhost,inv1,registered,sent
uid5,inv5@localhost,inv5,failed,sent
uid6,,inv6,uploaded,sent
uid7,new@localhost,inv7,uploaded,unsent
uid8,inv8@localhost,inv8,new,unsent
,empty,empty,new,unsent
unknown,,empty,new,unsent
"""

def test_import_mail(empty_db): #keys
    db = empty_db
    invs = gen_invitations(db)
    i6,i7 = invs[2], invs[3]
    i7.sent=SentStatusType.sent
    db.session.add_all(invs)
    db.import_invitations(StringIO(inv_mail))
    assert i6.status==StatusType.deleted
    assert i7.email=='new@localhost' 
    assert i7.status==StatusType.new and i7.sent==SentStatusType.unsent

def test_export(inv_db):
    invfile = StringIO()
    inv_db.export_invitations(invfile,allfields=True,format='csv')
    assert invfile.getvalue()==invitations

inv_small = """invitation,1.0
uuid,code,email
uid1,inv1,bar@localhost
uid5,inv5,inv5@localhost
uid6,inv6,inv6@localhost
uid7,inv7,inv7@localhost
uid8,inv8,inv8@localhost
"""

def test_export_small(inv_db):
    invfile = StringIO()
    inv_db.export_invitations(invfile,allfields=False,format='csv')
    assert invfile.getvalue()==inv_small

def test_export_crypt(inv_db,bilateral):
    inv_db.gpg = bilateral['id1']
    invfile = StringIO()
    inv_db.export_invitations(invfile,allfields=True,encrypt=receiver,sign=True,format='csv')
    id2 = bilateral['id2']
    result = id2.decrypt_str(invfile.getvalue())
    assert result.ok and result.valid
    assert str(result)==invitations

"""
backend,download -> backend,upload
new,-           -> new,new
new,new         -> uploaded,-
-,new           -> -,deleted
uploaded,new    -> uploaded,-
uploaded,registered -> registered+unsent,registered
uploaded,failed -> failed+unsent,failed
registered,registered -> registered,registered
failed,failed -> failed,failed
failed+sent,- -> new,new
new,failed    -> error or new,new ?
new,registered -> error
"""

inv_pre = {'format': 'invitation', 'version': [1, 0], 'fields': ['uuid','email','code','status','sent'], 
        'data': [
            ['uid01', 'inv1@localhost', 'inv1', 'new', 'unsent'],
            ['uid02', 'inv2@localhost', 'inv2', 'new', 'unsent'],
            ['uid04', 'inv4@localhost', 'inv4', 'uploaded', 'unsent'],
            ['uid05', 'inv5@localhost', 'inv5', 'uploaded', 'retry'],
            ['uid06', 'inv6@localhost', 'inv6', 'uploaded', 'sent'],
            ['uid07', 'inv7@localhost', 'inv7', 'registered', 'unsent'],
            ['uid08', 'inv8@localhost', 'inv8', 'failed', 'unsent'],
            ['uid09', 'inv9@localhost', 'inv9', 'failed', 'sent'],
            ['uid10', 'inv10@localhost', 'inv10', 'new', 'unsent'],
            ['uid11', 'inv11@localhost', 'inv11', 'new', 'unsent'],
        ]}

inv_down = {'format': 'invitation', 'version': [1, 0], 'fields': ['uuid', 'status'], 
        'data': [
            ['uid01', 'new'],

            ['uid03', 'new'],

            ['uid05', 'registered'],
            ['uid06', 'failed'],
            ['uid07', 'registered'],
            ['uid08', 'failed'],

            ['uid10', 'failed'],
            ['uid11', 'registered'],
        ]}

inv_up = {'format': 'invitation', 'version': [1, 0], 'fields': ['uuid', 'code','status'], 
        'data': [
            ['uid03', '', 'deleted'],
            ['uid05', 'inv5', 'registered'],
            ['uid06', 'inv6', 'failed'],
            ['uid07', 'inv7', 'registered'],
            ['uid08', 'inv8', 'failed'],
            ['uid02', 'inv2', 'new'],
            ['uid09', 'inv9', 'new'],
            ['uid10', 'inv10', 'new'],
            ['uid11', 'inv11', 'new'],
        ]}

inv_post = {'format': 'invitation', 'version': [1, 0], 'fields': ['uuid','email','code','status','sent'], 
        'data': [
            ['uid01', 'inv1@localhost', 'inv1', 'uploaded', 'unsent'],
            ['uid02', 'inv2@localhost', 'inv2', 'new', 'unsent'],

            ['uid04', 'inv4@localhost', 'inv4', 'uploaded', 'unsent'],
            ['uid05', 'inv5@localhost', 'inv5', 'registered', 'unsent'],
            ['uid06', 'inv6@localhost', 'inv6', 'failed', 'unsent'],
            ['uid07', 'inv7@localhost', 'inv7', 'registered', 'unsent'],
            ['uid08', 'inv8@localhost', 'inv8', 'failed', 'unsent'],
            ['uid09', 'inv9@localhost', 'inv9', 'new', 'unsent'],
            ['uid10', 'inv10@localhost', 'inv10', 'new', 'unsent'],
            ['uid11', 'inv11@localhost', 'inv11', 'new', 'unsent'],
        ]}

def test_export_json(empty_db):
    db = empty_db
    db.import_invitations(inv_pre,allfields=True,format='json')
    post = {}
    db.export_invitations(post,allfields=True,format='json')
    assert post == inv_pre


def check_sync(db,output):
    found = None
    data = output['data']
    for i,inv in enumerate(data):
        if inv[0]!='uid09': continue
        found = i
        break
    assert not found is None, "reset missing"
    assert data[found][1] != 'inv9',"new code missing"
    data[found][1] = 'inv9'
    assert output == inv_up
    db.session.query(db.Invitation).get('uid09').code = 'inv9'
    post = {}
    db.export_invitations(post,allfields=True,format='json')
    assert post == inv_post

def test_sync(empty_db):
    db = empty_db
    db.import_invitations(inv_pre,allfields=True,format='json')
    input = StringIO(json.dumps(inv_down))
    output = StringIO()
    db.sync_invitations(input=input,output=output)
    output = json.loads(output.getvalue())
    check_sync(db,output)

def test_sync_crypto(bilateral):
    from ekklesia.data import json_encrypt, json_decrypt
    apiconfig = dict(format='json',encrypt=True,sign=True,receiver=receiver)
    cfg = dict(def_config)
    db = setup_db(dict(config=def_config,apiconfig=apiconfig))
    db.import_invitations(inv_pre,allfields=True,format='json')

    id2 = bilateral['id2']
    input, result = json_encrypt(inv_down,id2,sender,True)
    assert result.ok
    input = StringIO(json.dumps(input))
    output = StringIO()
    db.gpg = bilateral['id1']
    db.sync_invitations(input=input,output=output)
    output = output.getvalue()
    output, encrypted, signed, result = json_decrypt(json.loads(output),id2)
    assert result.ok and result.valid
    check_sync(db,output)

@mark.parametrize("havesmtp", [False, True])
def test_send(empty_db, request, havesmtp, bilateral):
    "unsent/retry -> sent/failed"
    from ekklesia.mail import VirtualMailServer
    from kryptomime.pgp import find_gnupg_key
    import tempfile, shutil
    db = empty_db
    db.gpg = bilateral['id1']
    id2 = bilateral['id2']
    key1 = find_gnupg_key(bilateral['gpg1'],sender)
    db.import_invitations(inv_pre,allfields=True,format='json')

    tmpdir = tempfile.mkdtemp()
    server = VirtualMailServer(tmpdir)
    def fin():
        server.finish()
        shutil.rmtree(tmpdir,ignore_errors=True)
    request.addfinalizer(fin)
    accounts = {}
    if havesmtp:
        for i in range(1,12):
            accounts['uid%02i'%i] = server.add_account("inv%i@localhost" % i,keep=False)
    db.send_invitations(debug_smtp=server)
    changed = ['uid04','uid05','uid07','uid08']
    post = {}
    db.export_invitations(post,allfields=True,format='json')
    for i,inv in enumerate(post['data']):
        orig = inv_pre['data'][i]
        if not inv[0] in changed:
            assert inv == orig, "unexpected change"
            continue
        mod = list(orig)
        mod[4] = 'sent' if havesmtp else 'failed'
        assert inv == mod, "invalid change"
        if not havesmtp: continue
        imap = accounts[inv[0]]
        assert len(imap)==1
        for mail, flags in imap:
            mail, verified, result = id2.decrypt(mail,strict=False)
            assert mail and result
            assert not result['encrypted'] and result['signed'] and result['fingerprints']==[key1]

@mark.parametrize("uuids", [False, True])
def test_reset(inv_db, uuids):
    db = inv_db
    data = gen_invitations(db)
    if uuids: ids = [inv.uuid for inv in data]
    else: ids = [inv.email for inv in data]
    query = db.session.query(db.Invitation)

    db.reset_invitations(StringIO('\n'.join(ids[:2])),code=False,uuids=uuids)
    assert query.get('uid1').sent == SentStatusType.unsent
    assert query.get('uid5').sent == SentStatusType.unsent

    db.reset_invitations(StringIO(ids[2]),code=True,uuids=uuids)
    inv = query.get('uid6')
    assert inv.code != 'inv6'
    assert inv.status == StatusType.new and inv.sent == SentStatusType.unsent

inv_mailreset = {'format': 'invitation', 'version': [1, 0], 'fields': ['uuid','email','code','status','sent'], 
        'data': [
            ['uid01', 'inv1@localhost', 'inv1', 'new', 'unsent'],
            ['uid04', 'inv4@localhost', 'inv4', 'uploaded', 'unsent'],
            ['uid05', 'inv5@localhost', 'inv5', 'uploaded', 'sent'],
            ['uid06', 'inv6@localhost', 'inv6', 'uploaded', 'sent'],
        ]}

inv_mailupd = {'format': 'invitation', 'version': [1, 0], 'fields': ['uuid','email','code'], 
        'data': [
            ['uid04', 'change4@localhost', 'inv4'],
            ['uid05', 'change5@localhost', 'inv5'],
            ['uid06', 'inv6@localhost', 'inv6'],
        ]}

def test_reset_email(empty_db):
    db = empty_db
    db.import_invitations(inv_mailreset,allfields=True,format='json')
    db.import_invitations(inv_mailupd,allfields=False,format='json')
    post = {}
    db.export_invitations(post,allfields=True,format='json')
    for i in (1,2):
        oinv = inv_mailreset['data'][i][1:]
        ninv = post['data'][i][1:]
        if i==2:
            assert oinv[1] != ninv[1] and ninv[2:] == ['new','unsent']
        post['data'][i] = post['data'][i][:1]+oinv
    assert post == inv_mailreset
