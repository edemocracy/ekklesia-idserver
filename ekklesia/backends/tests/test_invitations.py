#!/usr/bin/env python
# coding: utf-8
#
# Tests for Invitation and Joint DB
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

import os, copy
from ekklesia.backends.invitations import InvitationDatabase, IStatusType, ISentStatusType
from ekklesia.backends.joint import MemberInvDatabase
from pytest import fixture, raises, mark
from ekklesia.tests.conftest import sender, receiver, third, keys, gpgsender, gpgreceiver, bilateral, passphrase
import logging, json
from sqlalchemy import create_engine
from six.moves import cStringIO as StringIO

members = """invitation,1.0
uuid,email
uid01,bar@localhost
uid05,inv5@localhost
uid06,inv6@localhost
uid07,inv7@localhost
uid08,inv8@localhost
"""

invitations = """invitation,1.0
uuid,email,code,status,sent
uid01,bar@localhost,inv1,registered,sent
uid05,inv5@localhost,inv5,failed,sent
uid06,inv6@localhost,inv6,uploaded,sent
uid07,inv7@localhost,inv7,uploaded,unsent
uid08,inv8@localhost,inv8,new,unsent
"""

minvitations = """invitation,1.0
uuid,code,status,sent
uid01,inv1,registered,sent
uid05,inv5,failed,sent
uid06,inv6,uploaded,sent
uid07,inv7,uploaded,unsent
uid08,inv8,new,unsent
"""

def gen_members(db):
    dep = db.Department(name='root')
    db.session.add(dep)
    out = []
    for i in range(1,13):
        email = 'inv%i@localhost'%i if i>1 else receiver
        member = db.Member(uuid='uid%02i'%i,email=email,department=dep)
        db.session.add(member)
        out.append(member)
    return out

def gen_invitations(db,ids=False):
    out = []
    init_data = [
        dict(uuid='uid01',code='inv1',email=receiver,status='registered',sent='sent'),
        dict(uuid='uid05',code='inv5',email='inv5@localhost',status='failed',sent='sent'),
        dict(uuid='uid06',code='inv6',email='inv6@localhost',status='uploaded',sent='sent'),
        dict(uuid='uid07',code='inv7',email='inv7@localhost',status='uploaded',sent='unsent'),
        dict(uuid='uid08',code='inv8',email='inv8@localhost',status='new',sent='unsent'),
    ]
    for i,inv in enumerate(init_data):
        if db.member_class:
            member = db.session.query(db.Member).filter_by(uuid=inv['uuid']).one()
            inv = dict(inv)
            del inv['uuid']
            del inv['email']
            obj = db.Invitation(member_id=member.uuid,**inv)
        else:
            obj = db.Invitation(**inv)
        if ids: obj.id = i+1
        out.append(obj)
    return out

def check_invs(db,invs=None,mini=False):
    if not invs: invs = gen_invitations(db)
    qinv = db.session.query(db.Invitation)
    assert len(invs) == qinv.count()
    for inv in invs:
        extra = {} if mini else dict(status=inv.status,sent=inv.sent)
        if db.member_class:
            tinv = qinv.filter_by(member_id=inv.member_id,**extra).one()
        else:
            tinv = qinv.filter_by(uuid=inv.uuid,email=inv.email,**extra).one()
        #assert not inv.id or inv.id==tinv.id

current_db = None # ugly workaround for pytest bug (finalizer not called immeditely)

def setup_db(dbtype=InvitationDatabase,engine=None,import_extra=[],reflect=True,**configs):
    import logging
    global current_db
    if current_db: current_db.drop_db()
    if dbtype==MemberInvDatabase:
        invite_import=['id','member_id','code','status','sent','lastchange']
    else:
        invite_import=['uuid','email','code','status','sent','lastchange']
    config = dict(invite_import=invite_import+import_extra,database=engine,io_key=receiver)
    db = dbtype().configure(config=config,gpgconfig=dict(sender=sender),**configs)
    db.setlogger('invitation','warning')
    log = logging.getLogger('sqlalchemy')
    log.setLevel(logging.WARNING)
    if not engine:
        engine = create_engine(db.database,echo=db.debugging)
    db.open_db(engine,mode='dropall')
    db.open_db(engine,mode='create')
    if reflect: db.open_db(engine,mode='open') # and reflect
    current_db = db
    return db

def stop_db(db,engine=None):
    global current_db
    if current_db!=db:
        print 'already finalized', db
        return
    db.drop_db()
    db.stoplogger()
    db.session.close()
    current_db = None

@fixture(scope='module')
def dbconnection(request):
    from sqlalchemy import create_engine
    db = request.config.getoption('db',None)
    if not db: return None
    return create_engine(db,echo=False)

@fixture(params=[InvitationDatabase,MemberInvDatabase],scope='module')
def dbsession(dbconnection, request):
    engine = dbconnection
    db = setup_db(request.param,engine=engine)
    request.addfinalizer(lambda: stop_db(db,engine))
    return db

@fixture
def empty_db(dbsession,request,monkeypatch):
    # Roll back at the end of every test
    db = dbsession
    if isinstance(db,MemberInvDatabase): gen_members(db)
    request.addfinalizer(db.session.rollback)
    monkeypatch.setattr(db.session, 'commit', db.session.flush)
    return db

@fixture
def inv_db(empty_db):
    db = empty_db
    db.session.add_all(gen_invitations(db))
    return db

def remove_email(data):
    data = copy.deepcopy(data)
    i = data['fields'].index('email')
    data['fields'].pop(i)
    for row in data['data']: row.pop(i)
    return data

def remove_lastchange(data,filled=True):
    if type(data)==dict:
        assert data['format']=='invitation'
        i = data['fields'].index('lastchange')
        data['fields'].pop(i)
        for row in data['data']:
            v = row.pop(i)
            assert not filled or v
        return data
    data = data.splitlines(False)
    assert data[0]=='invitation,1.0'
    f = data[1].split(',')
    i = f.index('lastchange')
    res = data[0]+'\n'
    for line in data[1:]:
        f = line.split(',')
        v = f.pop(i)
        assert not filled or v, 'lastchange missing'
        res += ','.join(f) + '\n'
    return res

@fixture(params=[InvitationDatabase,MemberInvDatabase],scope='module')
def noreflect_db(dbconnection,request):
    db = setup_db(request.param,reflect=False,engine=dbconnection)
    request.addfinalizer(lambda: stop_db(db,dbconnection))
    db.session.commit = db.session.flush
    return db

def test_import_init(noreflect_db):
    db = noreflect_db
    if isinstance(db,MemberInvDatabase): gen_members(db)
    db.import_invitations(StringIO(invitations))
    check_invs(db)
    db.session.rollback()

def test_import_basic(empty_db):
    db = empty_db
    db.import_invitations(StringIO(members))
    check_invs(db,mini=True)

def test_import_full(empty_db):
    db = empty_db
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
uid01,bar@localhost,inv1,registered,sent
uid01,foo@localhost,inv2,uploaded,sent
"""

minv_dup = """invitation,1.0
uuid,code,status,sent
uid01,inv1,registered,sent
uid01,inv2,uploaded,sent
"""

def test_import_dup(empty_db):
    with raises(AssertionError):
        empty_db.import_invitations(StringIO(inv_dup))

def test_reimport(inv_db): #keys
    inv_db.import_invitations(StringIO(invitations))
    check_invs(inv_db)

inv_mail = """invitation,1.0
uuid,email,code,status,sent
uid01,bar@localhost,inv1,registered,sent
uid05,inv5@localhost,inv5,failed,sent
uid06,,inv6,uploaded,sent
uid07,new@localhost,inv7,uploaded,unsent
uid08,inv8@localhost,inv8,new,unsent
,empty,empty,new,unsent
unknown,,empty,new,unsent
"""

members_mail = """member,1.0
uuid,email,status,department
uid01,bar@localhost,member,root
uid06,inv6@localhost,deleted,root
uid07,new@localhost,member,root
"""

def test_import_mail(empty_db):
    db = empty_db
    invs = gen_invitations(db)
    inv6, inv7 = invs[2:4]
    inv7.sent = ISentStatusType.sent # set both inv6 and 7 to uploaded,sent
    db.session.add_all(invs)
    if db.member_class:
        db.import_members(StringIO(members_mail)) # del uid06, change uid7
        query = db.session.query(db.Invitation)
        inv6 = query.filter_by(member_id='uid06').first()
        assert inv7.member.email=='new@localhost' and inv6.member.status=='deleted'
    else:
        db.import_invitations(StringIO(inv_mail))
        assert inv7.email=='new@localhost'
    assert inv6.status==IStatusType.deleted
    assert inv7.status==IStatusType.new and inv7.sent==ISentStatusType.unsent

inv_mailreset = {'format': 'invitation', 'version': [1, 0], 'fields': ['uuid','email','code','status','sent','lastchange'],
        'data': [
            ['uid01', receiver, 'inv1', 'new', 'unsent', None],
            ['uid04', 'inv4@localhost', 'inv4', 'uploaded', 'unsent', None],
            ['uid05', 'inv5@localhost', 'inv5', 'uploaded', 'sent', None],
            ['uid06', 'inv6@localhost', 'inv6', 'uploaded', 'sent', None],
        ]}

inv_mailupd = {'format': 'invitation', 'version': [1, 0], 'fields': ['uuid','email'],
        'data': [
            ['uid04', 'change4@localhost'],
            ['uid05', 'change5@localhost'],
            ['uid06', 'inv6@localhost'],
        ]}

def test_reset_email(empty_db):
    "change of email address should reset sent status for uploaded"
    db = empty_db
    input = remove_email(inv_mailreset) if db.member_class else copy.deepcopy(inv_mailreset)
    db.import_invitations(input,allfields=True,format='json')
    if db.member_class:
        update = copy.deepcopy(inv_mailupd)
        update['format'] = 'member'
        db.import_members(update,allfields=False,format='json')
    else:
        db.import_invitations(inv_mailupd,allfields=False,format='json')
    post = {}
    db.export_invitations(post,allfields=True,format='json')
    if not db.member_class:
        field_email = post['fields'].index('email')
    field_code = post['fields'].index('code')
    field_status = post['fields'].index('status')
    field_sent = post['fields'].index('sent')
    for i in (1,2):
        oinv = input['data'][i]
        ninv = post['data'][i]
        if not db.member_class:
            assert oinv[field_email] != ninv[field_email]
        if i==1: assert ninv[field_status] == 'uploaded'
        else: assert ninv[field_status] == 'new'
        assert ninv[field_sent] == 'unsent'
        assert (i==1) == (oinv[field_code] == ninv[field_code])
        post['data'][i] = list(oinv)
    assert remove_lastchange(post,filled=False) == remove_lastchange(input,filled=False)

def test_export(inv_db):
    invfile = StringIO()
    inv_db.export_invitations(invfile,allfields=True,format='csv')
    output = minvitations if inv_db.member_class else invitations
    assert remove_lastchange(invfile.getvalue())==output

inv_small = """invitation,1.0
uuid,code,email
uid01,inv1,bar@localhost
uid05,inv5,inv5@localhost
uid06,inv6,inv6@localhost
uid07,inv7,inv7@localhost
uid08,inv8,inv8@localhost
"""

minv_small = """invitation,1.0
uuid,code
uid01,inv1
uid05,inv5
uid06,inv6
uid07,inv7
uid08,inv8
"""

def test_export_small(inv_db):
    invfile = StringIO()
    inv_db.export_invitations(invfile,allfields=False,format='csv')
    data = minv_small if inv_db.member_class else inv_small
    assert invfile.getvalue()==data

def test_export_crypt(inv_db,bilateral):
    inv_db.gpg = bilateral['id1']
    invfile = StringIO()
    inv_db.export_invitations(invfile,allfields=True,
        encrypt=True,sign=True,format='csv')
    id2 = bilateral['id2']
    result = id2.decrypt_str(invfile.getvalue())
    assert result.ok and result.valid
    output = minvitations if inv_db.member_class else invitations
    assert remove_lastchange(str(result))==output

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

inv_pre = {'format': 'invitation', 'version': [1, 0],
        'fields': ['uuid','email','code','status','sent','lastchange'],
        'data': [
            ['uid01', receiver, 'inv1', 'new', 'unsent', None],
            ['uid02', 'inv2@localhost', 'inv2', 'new', 'unsent', None],
            ['uid04', 'inv4@localhost', 'inv4', 'uploaded', 'unsent', None],
            ['uid05', 'inv5@localhost', 'inv5', 'uploaded', 'retry', None],
            ['uid06', 'inv6@localhost', 'inv6', 'uploaded', 'sent', None],
            ['uid07', 'inv7@localhost', 'inv7', 'registered', 'unsent', None],
            ['uid08', 'inv8@localhost', 'inv8', 'failed', 'unsent', None],
            ['uid09', 'inv9@localhost', 'inv9', 'failed', 'sent', None],
            ['uid10', 'inv10@localhost', 'inv10', 'new', 'unsent', None],
            ['uid11', 'inv11@localhost', 'inv11', 'new', 'unsent', None],
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
            ['uid02', 'inv2', 'new'],
            ['uid03', '', 'deleted'],
            ['uid05', 'inv5', 'registered'],
            ['uid06', 'inv6', 'failed'],
            ['uid07', 'inv7', 'registered'],
            ['uid08', 'inv8', 'failed'],
            ['uid09', 'inv9', 'new'],
            ['uid10', 'inv10', 'new'],
            ['uid11', 'inv11', 'new'],
        ]}

inv_post = {'format': 'invitation', 'version': [1, 0], 'fields': ['uuid','email','code','status','sent'],
        'data': [
            ['uid01', receiver, 'inv1', 'uploaded', 'unsent'],
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
    input = remove_email(inv_pre) if db.member_class else copy.deepcopy(inv_pre)
    db.import_invitations(input,allfields=True,format='json')
    post = {}
    db.export_invitations(post,allfields=True,format='json')
    assert remove_lastchange(post) == remove_lastchange(input,filled=False)

def sort_by_uuid(data):
    return sorted(data,key=lambda x: x[0])

def check_sync(db,output):
    data = sort_by_uuid(output['data'])
    found = False
    for i,inv in enumerate(data):
        if inv[0]!='uid09': continue
        assert inv[1] != 'inv9',"new code missing"
        inv[1] = 'inv9'
        found = True
        break
    assert found, "reset missing"
    output['data'] = data
    assert output == inv_up
    if db.member_class:
        inv9 = db.session.query(db.Invitation).filter_by(member_id='uid09').first()
    else:
        inv9 = db.session.query(db.Invitation).get('uid09')
    inv9.code = 'inv9'
    post = {}
    db.export_invitations(post,allfields=True,format='json')
    output = remove_email(inv_post) if db.member_class else inv_post
    assert remove_lastchange(post) == output

def test_sync(empty_db):
    db = empty_db
    input = remove_email(inv_pre) if db.member_class else inv_pre
    db.import_invitations(input,allfields=True,format='json')
    input = StringIO(json.dumps(inv_down))
    output = StringIO()
    db.sync_invitations(input=input,output=output)
    output = json.loads(output.getvalue())
    check_sync(db,output)

@mark.parametrize('newstatus',['registered','failed'])
def test_push(empty_db,newstatus):
    db = empty_db
    input = remove_email(inv_pre) if db.member_class else inv_pre
    db.import_invitations(input,allfields=True,format='json')
    input = copy.deepcopy(inv_down)
    input['data'] = input['data'][2:]
    input = StringIO(json.dumps(input))
    output = StringIO()
    # ignore registering
    msg = dict(format='member',version=(1,0),status='',uuid='uid06')
    for status in ('registering','new'):
        msg['status'] = status
        assert not InvitationDatabase.process_update(db,msg,input,output)
        assert not output.getvalue()
    # registered leads to sync
    msg['status'] = newstatus
    assert InvitationDatabase.process_update(db,msg,input,output)
    output = json.loads(output.getvalue())
    assert output
    up = copy.deepcopy(inv_up)
    up['data'] = up['data'][2:6]
    output['data'] = sort_by_uuid(output['data'])
    assert output == up
    # not again
    assert not db.process_update(msg,input,output)

@fixture(params=[InvitationDatabase,MemberInvDatabase],scope='module')
def crypto_db(dbconnection,request):
    dbtype = request.param
    apiconfig = dict(format='json',encrypt=True,sign=True,receiver=receiver)
    extra = dict(apiconfig=apiconfig) if dbtype==InvitationDatabase else dict(invconfig=apiconfig)
    db = setup_db(dbtype,engine=dbconnection,**extra)
    if isinstance(db,MemberInvDatabase):
        gen_members(db)
    request.addfinalizer(lambda: stop_db(db,dbconnection))
    db.session.commit = db.session.flush
    return db

def test_sync_crypto(bilateral,crypto_db):
    from ekklesia.data import json_encrypt, json_decrypt
    db = crypto_db
    input = remove_email(inv_pre) if db.member_class else inv_pre
    db.import_invitations(input,allfields=True,format='json')

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
    db.session.rollback()

@mark.parametrize("havesmtp", [False, True])
def test_send(request, empty_db, havesmtp, bilateral):
    "unsent/retry -> sent/failed"
    from ekklesia.mail import VirtualMailServer
    from kryptomime.pgp import find_gnupg_key
    import tempfile, shutil
    db = empty_db
    db.gpg = bilateral['id1']
    id2 = bilateral['id2']
    key1 = find_gnupg_key(bilateral['gpg1'],sender)
    input = remove_email(inv_pre) if db.member_class else inv_pre
    db.import_invitations(input,allfields=True,format='json')

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
    field_uuid = post['fields'].index('uuid')
    field_sent = input['fields'].index('sent')
    field_lchange = post['fields'].index('lastchange')
    for i,inv in enumerate(post['data']):
        orig = input['data'][i]
        assert inv[field_lchange]
        inv[field_lchange] = None # delete lastchange
        if not inv[field_uuid] in changed:
            assert inv == orig, "unexpected change"
            continue
        mod = list(orig)
        mod[field_sent] = 'sent' if havesmtp else 'failed'
        assert inv == mod, "invalid change"
        if not havesmtp: continue
        imap = accounts[inv[field_uuid]]
        assert len(imap)==1
        for mail, flags in imap:
            mail, verified, result = id2.decrypt(mail,strict=False)
            assert mail and result
            assert not result['encrypted'] and result['signed'] and result['fingerprints']==[key1]

@mark.parametrize("uuids", [False, True])
def test_reset(inv_db, uuids):
    db = inv_db
    if db.member_class and not uuids: return
    data = gen_invitations(db)
    if db.member_class:
        ids = [inv.member_id for inv in data]
    else:
        if uuids: ids = [inv.uuid for inv in data]
        else: ids = [inv.email for inv in data]
    query = db.session.query(db.Invitation)

    db.reset_invitations(StringIO('\n'.join(ids[:2])),code=False,uuids=uuids)
    if db.member_class:
        assert query.filter_by(member_id='uid01').one().sent == ISentStatusType.unsent
        assert query.filter_by(member_id='uid05').one().sent == ISentStatusType.unsent
    else:
        assert query.get('uid01').sent == ISentStatusType.unsent
        assert query.get('uid05').sent == ISentStatusType.unsent

    db.reset_invitations(StringIO(ids[2]),code=True,uuids=uuids)
    if db.member_class:
        inv = query.filter_by(member_id='uid06').one()
    else:
        inv = query.get('uid06')
    assert inv.code != 'inv6'
    assert inv.status == IStatusType.new and inv.sent == ISentStatusType.unsent

def test_empty(empty_db):
    db = empty_db
    assert not db.session.query(db.Invitation).count()
