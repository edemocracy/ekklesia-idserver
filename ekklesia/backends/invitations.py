#!/usr/bin/env python
# coding: utf-8
#
# Invitation code database
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

"""
This is the invitation database (see members database for more details on the registration process).
It can be combined with the member database into a joint database.
The separation makes it possible to reset invitation codes without access to the more sensitive
member database.

Data formats used for import/export/sync:

fields (format: invitation 1.0):
uuid    - unique member id (UUID max.36)
email   - email adress (if not joint db)
code - unique invitation code (max.36)
status  - new, uploaded, failed, registered, deleted
sent    - unsent, sent, retry, failed
lastchange - UTC datetime when status was changed, email was sent, or null
optional for sync:
echo    - return in response
check_email - email to check, return 0/1 response if not empty

import fields: uuid(,email if not joint)
export fields: uuid,code(,email if not joint)
sync download: uuid,status[,check_email][,echo]
sync upload: uuid,status,code[,check_email][,echo]
 echo or check_email if in download and enabled
reset data: simple linewise list of emails or uuids

sync state transitions:
backend,idserver -> target
new,-         -> idserver:new
new,new       -> idserver:new, backend:uploaded
-,any         -> backend:deleted,error
uploaded,new /-> idserver
uploaded,new  -> backend:uploaded
uploaded,reging-> backend:uploaded
uploaded,reg  -> backend:registered
uploaded,fail -> backend:fail
reg,reg       -> backend:reg, idserver:delete
fail,fail     -> backend:fail, idserver:delete (or new,new)
fail,-        -> backend:new (check if fail not downloaded)

requirements: Python >=2.7, sqlalchemy, gnupg, requests
"""

from __future__ import print_function, absolute_import
from ekklesia.backends import (AbstractDatabase, api_defaults,
    FileMissingWarning, UnknownFieldsWarning, DeclEnum, EnumSymbol)
from ekklesia.mail import gpg_defaults, smtp_defaults
from ekklesia import FormattedWarning

class IStatusType(DeclEnum):
    deleted = EnumSymbol('deleted')
    new = EnumSymbol('new')
    uploaded = EnumSymbol('uploaded')
    failed = EnumSymbol('failed')
    registered = EnumSymbol('registered')

class ISentStatusType(DeclEnum):
    unsent = EnumSymbol('unsent')
    sent = EnumSymbol('sent')
    retry = EnumSymbol('retry')
    failed = EnumSymbol('failed')

invitations_spec ='''
[invitations]
# the table name for invitations
invite_table = string(default='invitations')
# columns to import from the table
invite_import = string_list(default=list('uuid','email','code','status','sent','lastchange'))
# allow check_email, if empty disabled
invite_check_email = string
# email template for invitations
invite_subject = string(default='Invitation Code')
invite_body = string(default="""Dear member,\\nYou're welcome to sign up for Ekklesia.\\nPlease your following personal link to sign up\\n<%s>\\nWarning: Do not forward or show this message to anyone else.\\nOtherwise someone else sign up in your name with this link.\\nThank you""")
invite_url = string(default='https://localhost/register?code=%s')
invite_sign = boolean(default=True) # sign invitation emails
invite_notify = boolean(default=True) # send confirmation after registration
# email template for registration confirmation
registered_subject = string(default='Registration successful')
registered_body = string(default="Your account has been successfully registered")
# email template for failure notification
failed_subject = string(default='Registration failed')
failed_body = string(default="Your account registration has failed. You're going to receive another invitation soon.")
# required signature for import, receiver for export
io_key = string
broker = string
broker_exchange = string(default='id-backend')
broker_queue = string(default='id-invitations')
'''

class InvitationDatabase(AbstractDatabase):
    version = [1,0]
    
    def __init__(self, *args, **kwargs):
        super(InvitationDatabase,self).__init__(*args, **kwargs)
        self.invite_api = None
        self.smtpconfig = None
        self.member_class = None

    def configure(self,config={},gpgconfig=gpg_defaults,apiconfig=api_defaults,
        smtpconfig=smtp_defaults):
        from ekklesia.backends import APIConfig, spec_defaults
        super(InvitationDatabase,self).configure(config=config,gpgconfig=gpgconfig)
        api = api_defaults.copy()
        api.update(apiconfig)
        self.invite_api = APIConfig(**api)
        self.smtpconfig = smtpconfig
        self.member_class = None # integrated with Member table
        assert self.version[0]<=1, 'invalid version'
        defaults = spec_defaults(invitations_spec)['invitations']
        for key in defaults.keys():
            setattr(self,key,config.get(key,defaults[key]))
        return self

    def init_parser_reset(self,subparsers):
        parser = subparsers.add_parser('reset', help='reset sent status or invite codes')
        parser.add_argument("-i", "--invite", action="store_true", default=False, help="reset invite codes, otherwise only sent status")
        parser.add_argument("-u", "--uuid", action="store_true", default=False, help="file contains uuids, otherwise emails")
        parser.add_argument("file",help='file with emails/uuids')
        return parser

    def init_parser_send(self,subparsers):
        parser = subparsers.add_parser('send', help='send emails to members')
        return parser

    def init_parser_sync(self,subparsers,twopass=False):
        parser = super(InvitationDatabase,self).init_parser_sync(subparsers)
        parser.add_argument("-m", "--mails",metavar='MAILS', help='output file for unregistered members')
        parser.add_argument("-a", "--ack", action="store_false", help="do not acknowledge uploads")
        return parser

    def init_parsers(self,name,description):
        parser, subparsers = self.init_parser_main(name,description)
        self.init_parser_init(subparsers)
        self.init_parser_import(subparsers)
        self.init_parser_export(subparsers)
        self.init_parser_sync(subparsers)
        self.init_parser_push(subparsers)
        self.init_parser_reset(subparsers)
        self.init_parser_send(subparsers)
        return parser, subparsers

    def declare(self,reflect=True):
        from sqlalchemy import (Table, Column, ForeignKey,
            Sequence, Integer, String, Boolean, DateTime, func)
        from sqlalchemy.orm import relationship, backref
        from ekklesia.data import init_object, repr_object
        from datetime import datetime

        class Invitation(self.Base):
            if not reflect:
                __tablename__ = self.invite_table
                if self.member_class:
                    id = Column(Integer, Sequence('id_seq',optional=True), primary_key=True)
                    member_id = Column(String(36),
                        ForeignKey(self.member_class.uuid,name='member_fk'), nullable=False)
                else:
                    uuid = Column(String(36), primary_key=True)
                    email = Column(String(254), nullable=False, unique=True, index=True)
                code = Column(String(36), nullable=False, unique=True)
                status = Column(IStatusType.db_type(), nullable=False, default=IStatusType.new)
                sent = Column(ISentStatusType.db_type(), nullable=False, default=ISentStatusType.unsent)
                lastchange = Column(DateTime, nullable=True, default=datetime.utcnow)
            else: # pragma: no cover
                __table__ = Table(self.invite_table, self.Base.metadata,
                    Column('status',IStatusType.db_type(), nullable=False, default=IStatusType.new),
                    Column('sent',ISentStatusType.db_type(), nullable=False, default=ISentStatusType.unsent),
                    autoload=True)
                if 'invitations' in self.column_map:
                    __mapper_args__ = {'include_properties' : list(self.column_map['invitations'].keys()) }
            if self.member_class:
                member = relationship(self.member_class, backref=backref("invitation", uselist=False))

            def __init__(inv, status=IStatusType.new, sent=ISentStatusType.unsent, lastchange=None, **kwargs):
                super(self.Base,inv).__init__()
                from uuid import uuid4
                if 'uuid' in kwargs: assert kwargs['uuid'], "uuid missing"
                if 'code' in kwargs: value = kwargs['code']
                else: value = str(uuid4())
                kwargs['code'] = value
                kwargs['status'] = status
                kwargs['sent'] = sent
                kwargs['lastchange'] = lastchange or datetime.utcnow()
                inv.update(**kwargs)

            def update(inv, **kwargs):
                init_object(inv,**kwargs)
                if not 'lastchange' in kwargs: inv.change()

            def reset(inv, status=IStatusType.new):
                from uuid import uuid4
                if status:
                     inv.status = status
                     if status == IStatusType.new:
                         inv.code = str(uuid4())
                inv.sent = ISentStatusType.unsent
                inv.change()

            def delete(inv):
                inv.status = IStatusType.deleted
                inv.change()

            def change(inv):
                inv.lastchange = datetime.utcnow()

            def __repr__(inv):
                return repr_object(inv,self.invite_columns)

        self.Invitation = Invitation

    def reflect_classes(self):
        from ekklesia.backends import reflect_class
        from ekklesia.data import frozendict
        self.invite_columns, invite_types = reflect_class(self.Invitation)
        self.invite_types = frozendict(invite_types)

    def import_invitations(self,input,decrypt=False,verify=False,
            allfields=False,sync=False,dryrun=False,format='csv'):
        """import data from input.
        allfields is used for restore and requires all columns.
        if sync, uuids not seen in input are set to status deleted.
        decrypt=with the default key, verify=check whether its signed with io_key.
        """
        from ekklesia.data import DataTable
        session = self.session
        Invitation = self.Invitation
        membercls = self.member_class
        columns = self.invite_columns
        if membercls:
            columns = list(columns)+['uuid']
            columns.remove('id')
        if allfields: reqcolumns = columns
        elif membercls: reqcolumns = ['uuid']
        else: reqcolumns = ['uuid','email']
        reader = DataTable(columns,coltypes=self.invite_types,required=reqcolumns,
            dataformat='invitation',fileformat=format,version=self.version,gpg=self.gpg)
        if not allfields and verify: verify = self.io_key
        reader.open(input,'r',encrypt=decrypt,sign=verify)
        columns = reader.get_columns()[0]
        iquery = session.query(Invitation)
        count = 0
        seen = set()
        for data in reader:
            uuid = data['uuid']
            if not uuid:
                self.warn("uuid missing")
                continue
            assert not uuid in seen, "member %s is duplicate" % uuid
            seen.add(uuid)
            if membercls:
                member = session.query(membercls).filter_by(uuid=uuid).first()
                if member is None:
                    self.warn("uuid %s not found" % uuid)
                    continue
                if not member.email: # email removed, disable invitation
                    inv = member.invitation
                    if inv and not inv.status in (IStatusType.deleted,IStatusType.registered):
                        self.info("scheduling invitation for uuid '%s' for deletion", member.uuid)
                        if not dryrun: inv.delete()
                    continue
                count += 1
                if dryrun: continue
                if member.invitation is None: # create a new invitation
                    session.add(Invitation(member=member,**data)) #new
                else:
                    if not 'sent' in columns and data['status'] in (IStatusType.new,IStatusType.uploaded):
                        data['sent'] = ISentStatusType.unsent
                    member.invitation.update(**data) #update inv
            else:
                inv = iquery.filter_by(uuid=uuid).first()
                if not data['email']: # email removed, disable invitation
                    if inv is None:
                        self.warn("uuid %s not found" % uuid)
                        continue
                    if inv.status in (IStatusType.deleted,IStatusType.registered): continue
                    self.info("scheduling invitation for uuid '%s' for deletion", inv.uuid)
                    if not dryrun: inv.delete()
                    continue
                # check whether email already used
                if not inv or inv.email != data['email']:
                    # fixme: what if emails swapped?
                    email = iquery.filter_by(email=data['email']).first()
                    if email and (not inv or inv.uuid != email.uuid):
                        self.error("ignoring: duplicate email %s" % data['email'])
                        continue
                count += 1
                if dryrun: continue
                if inv:
                    # if email changed and code has been sent, reset invcode and lastchange, unless allfields is set
                    needreset = not allfields and inv.status==IStatusType.uploaded and \
                         inv.sent==ISentStatusType.sent and 'email' in data and data['email']!=inv.email and \
                         (not 'code' in data or data['code']==inv.code)
                    if not needreset: data['code'] = inv.code # preserve
                    inv.update(**data)
                    if needreset: inv.reset()
                else:
                    session.add(Invitation(**data)) #new
        self.info('%i imported invitations', count)
        if sync: # deleted unseen invitations
            count = 0
            for inv in session.query(membercls if membercls else Invitation).yield_per(1000):
                uuid = inv.uuid
                if uuid in seen: continue
                if membercls:
                    inv = inv.invitation
                    if not inv: continue
                if inv.status==IStatusType.deleted: continue
                inv.status = IStatusType.deleted
                self.info("invitation %s deleted" % uuid)
                count += 1
            self.info('%i deleted invitations', count)
        if not dryrun: session.commit()

    def export_invitations(self,output,allfields=False,encrypt=None,sign=False,format='csv'):
        """export invitations, sorted by primary (id, or uuid if joint), to output.
        allfields is used for backup and writes all columns.
        encrypt=to io_key, sign=with default key.
        """
        from ekklesia.data import DataTable
        session = self.session
        Invitation = self.Invitation
        membercls = self.member_class
        if allfields:
            if membercls:
                columns = ['uuid']+list(self.invite_columns)
                columns.remove('id')
            else: columns = self.invite_columns
        else:  # restricted
            columns = ['uuid','code']
            if not membercls: columns += ['email']
        if encrypt: encrypt = [self.io_key]
        writer = DataTable(columns,coltypes=self.invite_types,gpg=self.gpg,
            dataformat='invitation',fileformat=format,version=self.version)
        writer.open(output,'w',encrypt=encrypt,sign=sign)
        count = 0
        for inv in session.query(Invitation).order_by(
            Invitation.id if membercls else Invitation.uuid).yield_per(1000):
            extra = {}
            if membercls: extra['uuid'] = inv.member.uuid
            writer.write(inv,extra)
            count += 1
        writer.close()
        self.info('%i exported invitations', count)

    def sync_invitations(self,download=True,upload=True,dryrun=False,quick=False,input=None,output=None):
        "sync invitations with ID server"
        from ekklesia.backends import api_init
        from ekklesia.data import DataTable
        from six.moves import cStringIO as StringIO
        import requests, json
        session = self.session
        Invitation = self.Invitation
        membercls = self.member_class
        check_email = self.invite_check_email
        api = api_init(self.invite_api._asdict())
        reply = False # whether server requested reply
        if download: # download registered uuids(used codes), mark used
            if input: input = json.load(input)
            if not input: # pragma: no cover
                url = self.invite_api.url
                if quick: url+='?changed=1'
                resp = api.get(url)
                if resp.status_code != requests.codes.ok:
                    if self.debugging: open('invdown.html','w').write(resp.content)
                    assert False, 'cannot download used invite codes'
                input = resp.json()
            if not input:
                self.warn("input is empty")
                return
            columns = ['uuid','status','echo']
            if check_email: columns.append(check_email)
            reader = DataTable(columns,coltypes=self.invite_types,required=('uuid','status'),gpg=self.gpg,
                dataformat='invitation',fileformat=self.invite_api.format,version=self.version)
            sign = self.invite_api.receiver if self.invite_api.sign else False
            reader.open(input,'r',encrypt=self.invite_api.encrypt,sign=sign)
            rcolumns, unknown = reader.get_columns()
            if unknown: self.warn('ignoring unknown fields',unknown)
            reply = 'echo' in rcolumns # reply?
            if check_email: reply = reply or check_email in rcolumns
        if upload:
            # upload responses and non-uploaded,unused uuid&code
            columns = ['uuid','code','status']
            coltypes = self.invite_types.copy()
            if check_email: coltypes[check_email] = bool
            if download and reply:
                if check_email and check_email in rcolumns: columns.append(check_email)
                if 'echo' in rcolumns: columns.append('echo')
            writer = DataTable(columns,coltypes=coltypes,gpg=self.gpg,
                    dataformat='invitation',fileformat=self.invite_api.format,version=self.version)
            encrypt = [self.invite_api.receiver] if self.invite_api.encrypt else False
            out = {}
            writer.open(out,'w',encrypt=encrypt,sign=self.invite_api.sign)
        if download: # process download and generate reply
            if membercls: query = session.query(membercls)
            else: query = session.query(Invitation)
            count = 0
            seen = set()
            for data in reader: # only uploaded codes, reply optional
                uuid = data['uuid']
                if not uuid:
                    self.warn("uuid missing")
                    continue
                if uuid in seen:
                    self.warn("member %s is duplicate" % uuid)
                    continue
                seen.add(uuid)
                status = data['status']
                if not status in ('registered','failed','new') or (quick and status=='new'):
                    self.warn("invalid status %s for %s" % (status,uuid))
                    continue
                inv = query.filter_by(uuid=uuid).first()
                extra = {}
                if membercls and inv:
                    inv = inv.invitation
                if not inv:
                    self.error("member %s is unknown" % data['uuid'])
                    if check_email in columns and data[check_email]:
                        extra[check_email] = False
                    extra['uuid'] = uuid
                    writer.write(Invitation(status=IStatusType.deleted,code=''),extra)
                    continue
                status = data['status'] # compare status
                # new on new -> uploaded
                # new on uploaded -> ignore
                # registered/failed on uploaded -> registered/failed
                # registered/failed on same -> ignore
                # deleted on failed -> new
                if status == IStatusType.new:
                    if inv.status == IStatusType.new:
                        inv.status = IStatusType.uploaded
                        inv.sent = ISentStatusType.unsent
                    elif inv.status != IStatusType.uploaded:
                        self.error("bad status %s for uuid %s, current %s",
                             status,data['uuid'],inv.status)
                        continue
                elif inv.status == IStatusType.uploaded: # status in registered/failed
                    if inv.status != status: inv.change()
                    inv.status = status # upload confirmed or failed registration
                    inv.sent = ISentStatusType.unsent
                elif status != inv.status:
                    self.error("bad status %s for uuid %s, current %s",
                        status, data['uuid'],inv.status)
                    continue
                if upload and (status != IStatusType.new or reply): # write response for uploaded
                    if check_email and check_email in columns:
                        if member_class: extra[check_email] = inv.member.email == data[check_email]
                        else: extra[check_email] = inv.email == data[check_email]
                    if 'echo' in columns: extra['echo'] = data['echo']
                    if membercls: extra['uuid'] = data['uuid']
                    writer.write(inv,extra)
                count += 1
            self.info('%i codes used', count)
            if not dryrun: session.commit()
        if not upload: return
        # process failed, which have already been deleted on the server and are ready for reset
        count = 0
        query = session.query(Invitation).filter_by(status=IStatusType.failed,
            sent=ISentStatusType.sent)
        for inv in query.yield_per(1000):
            extra = {}
            if membercls: uuid = inv.member.uuid
            else: uuid = inv.uuid
            if uuid in seen: continue # already replied
            inv.reset()
            count += 1
        self.info('%i codes resetted', count)
        if not dryrun: session.commit()
        if not quick:
            # append new invitations
            count = 0
            query = session.query(Invitation).filter_by(status=IStatusType.new)
            for inv in query.yield_per(1000):
                extra = {}
                if membercls:
                    uuid = inv.member.uuid
                    extra['uuid'] = uuid
                else: uuid = inv.uuid
                writer.write(inv,extra)
                count += 1
            self.info('%i new codes uploaded', count)
        writer.close()
        if output:
            json.dump(out,output)
        elif not dryrun: # pragma: no cover
            resp = api.post(self.invite_api.url,json=out)
            if resp.status_code != requests.codes.ok:
                if self.debugging: open('invup.html','w').write(resp.content)
                assert False, 'cannot upload data'

    def process_update(self,msg,input=None,output=None):
        "process update valid messages with changing to registered/failed status"
        self.info('got update %s',msg)
        version = msg.get('version')
        if not (msg and msg.get('format')=='member' and len(version)==2):
            self.warn('invalid message')
            return False
        if version[0]!=1:
            self.warn('invalid message version %s', version)
            return False
        status, uuids = msg.get('status'), msg.get('uuid')
        if not (status and uuids):
            self.warn('invalid status %s or uuid %s', status, uuids)
            return False
        if not status in ('registered','failed'):
            self.debug('ignoring status %s', status)
            return False
        if not isinstance(uuids,list): uuids = [uuids]
        membercls = self.member_class
        if membercls: query = self.session.query(membercls)
        else: query = self.session.query(self.Invitation)
        found = False
        for uuid in uuids:
            inv = query.filter_by(uuid=uuid).first()
            if membercls and inv: inv = inv.invitation
            if not inv:
                self.warn('uuid invitation not found %s', uuid)
                continue
            if inv.status in (IStatusType.registered,IStatusType.failed):
                self.warn('uuid has already been updated %s', uuid)
            else: found = True
        if not found: return False
        self.sync_invitations(self,quick=True,input=input,output=output)
        return True

    def reset_invitations(self,input,code=False,uuids=False,dryrun=False):
        """reset invitations for the members in input (linewise).
        if uuids, the list contains the uuids, otherwise the emails.
        if code, reset the code and status, otherwise only the sent status.
        """
        session = self.session
        Invitation = self.Invitation
        membercls = self.member_class
        count = 0
        if membercls: query = session.query(membercls)
        else: query = session.query(Invitation)
        for line in input:
            line = line.rstrip()
            if uuids: inv = query.filter_by(uuid=line).first()
            else: inv = query.filter_by(email=line).first()
            if inv is None:
                self.error('member %s not found' % line)
                continue
            if membercls:
                inv = inv.invitation
                if not inv:
                    self.error('invitation for %s not found' % line)
                    continue
            if code:
                from uuid import uuid4
                if inv.status==IStatusType.registered:
                    self.error('member %s has already used the code' % line)
                    continue
                if inv.status==IStatusType.deleted:
                    self.error('member %s is already deactivated' % line)
                    continue
                count +=1
                if dryrun: continue
                inv.reset() # new code and set to new/unsent
            else:
                count +=1
                if not dryrun: inv.reset(status=None) # set only to unsent
        self.info('%i resets', count)
        if not dryrun: session.commit()

    def create_mail(self,status,inv,sender,email,code=None):
        "create mail using the status dependent template"
        from kryptomime import create_mail
        if status == IStatusType.uploaded:
            link = self.invite_url % inv.code
            subject, body = self.invite_subject,self.invite_body.decode('string_escape') % link
        elif status == IStatusType.registered:
            subject, body = self.registered_subject, self.registered_body.decode('string_escape')
        else: # status == IStatusType.failed:
            subject, body = self.failed_subject, self.failed_body.decode('string_escape')
        return create_mail(sender,email,subject,body)

    def send_invitations(self,dryrun=False,debug_smtp=None):
        "send emails to all uploaded/registered/failed and not already sent invitations"
        from ekklesia.mail import smtp_init
        import smtplib
        session = self.session
        Invitation = self.Invitation
        if debug_smtp: smtp = debug_smtp
        else: # pragma: no cover
            smtp = smtp_init(self.smtpconfig)
            smtp.open()
        sender = self.gpgconfig['sender']
        query = session.query(Invitation)
        stati = [IStatusType.uploaded,IStatusType.registered,IStatusType.failed]
        query = query.filter(Invitation.status.in_(stati)) # not deleted/new
        sstati = [ISentStatusType.unsent,ISentStatusType.retry]
        query = query.filter(Invitation.sent.in_(sstati))
        count = 0
        while True:
            inv = query.first() # no commits during yield_per
            if not inv: break
            if self.member_class: email = inv.member.email
            else: email = inv.email
            self.info('sending %s status %s to %s', inv.code, inv.status, email)
            msg = self.create_mail(inv.status,inv,sender,email,inv.code)
            if self.invite_sign:
                msg, results = self.gpg.sign(msg,inline=True,default_key=True,verify=True)
                if not msg:
                    self.error('signing message for %s' % email)
                    break
            if not dryrun:
                try:
                    smtp.send(msg)
                    inv.sent = ISentStatusType.sent
                except smtplib.SMTPRecipientsRefused:
                    inv.sent = ISentStatusType.failed # failed
                except (smtplib.SMTPDataError,smtplib.SMTPSenderRefused,smtplib.SMTPHeloError):
                    inv.sent = ISentStatusType.retry # retry
                inv.change()
                session.commit() # critical data
            count +=1
        if not debug_smtp: smtp.close()
        self.info('%i emails successfully sent', count)

    def run_import_invitations(self, args, input): # pragma: no cover
        from ekklesia.data import special_openwith
        if args.dryrun: self.info('simulating import')
        with special_openwith(input, 'r') as f:
            self.import_invitations(f,decrypt=args.decrypt,verify=args.verify,
                dryrun=args.dryrun,allfields=args.all,sync=args.sync)

    def run_export_invitations(self, args, output): # pragma: no cover
        from ekklesia.data import special_openwith
        with special_openwith(output, 'w') as f:
            self.export_invitations(f,encrypt=args.encrypt,
                sign=args.sign,allfields=args.all)

    def run_push_invitations(self, args): # pragma: no cover
        if not args.daemon:
            import signal
            signal.signal(signal.SIGHUP, self.terminate)
            signal.signal(signal.SIGINT, self.terminate)
        assert not self.invite_api.sign or self.gpgconfig['sender'], 'sender for signing missing'
        if args.dryrun: self.info('simulating push')
        self.push_sync(upload=args.upload,delay=args.wait,dryrun=args.dryrun)

    def run_sync_invitations(self, args): # pragma: no cover
        from ekklesia.data import special_open
        assert not self.invite_api.sign or self.gpgconfig['sender'], 'sender for signing missing'
        if args.output: assert len(args.output)==1, "only one output file expected"
        if args.dryrun: self.info('simulating sync')
        input = special_open(args.input,'r') if args.input else None
        output = special_open(args.output[0],'w') if args.output else None
        self.sync_invitations(download=args.download,upload=args.upload,quick=args.quick,
            input=input,output=output,dryrun=args.dryrun)
        if args.ack and not args.quick: # acknowledge new uploads so they can be sent
            self.sync_invitations(download=True,upload=False,dryrun=args.dryrun)

    def run_reset_invitations(self, args): # pragma: no cover
        from ekklesia.data import special_openwith
        if args.dryrun: self.info('simulating reset')
        with special_openwith(args.file, 'r') as f:
            self.reset_invitations(f,code=args.invite,uuids=args.uuid,dryrun=args.dryrun)

    def run(self, args=None): # pragma: no cover
        from ekklesia.data import special_openwith, dummy_context
        from ekklesia.backends import api_spec, session_context
        from ekklesia.mail import gpg_spec, smtp_spec
        from sqlalchemy import create_engine
        args, parser = self.init_run('invitations','invitation script for members',args)
        spec = invitations_spec+gpg_spec+smtp_spec+api_spec('invitation_api')
        config = self.get_configuration(spec,args,'invitations.ini')
        self.configure(config=config['invitations'],gpgconfig=config['gnupg'],
            apiconfig=config['invitation_api'],smtpconfig=config['smtp'])
        self.init_gnupg()
        if args.command=='push' and args.daemon:
            daemon = self.prepare_daemon(args.pid)
        else: daemon = dummy_context()
        with daemon, session_context(self):
            engine = create_engine(self.database,echo=False) #, echo=self.debugging
            if args.command == 'init':
                if args.drop:
                    self.info('dropping tables')
                    self.open_db(engine,mode='dropall' if args.all else 'drop')
                self.open_db(engine,mode='create')
                self.info('database intialized')
                if args.initial:
                    with special_openwith(args.initial[0], 'r') as f:
                        self.import_invitations(f,allfields=True)
                return
            self.open_db(engine,mode='open')
            if args.command == 'import':
                self.run_import_invitations(args, args.file)
            elif args.command == 'export':
                self.run_export_invitations(args, args.file)
            elif args.command == 'sync':
                self.run_sync_invitations(args)
            elif args.command == 'push':
                self.run_push_invitations(args)
            elif args.command == 'reset':
                self.run_reset_invitations(args)
            elif args.command == 'send':
                if args.dryrun: self.info('simulating send')
                self.send_invitations(dryrun=args.dryrun)

def main_func(): # pragma: no cover
    InvitationDatabase().run()

if __name__ == "__main__": main_func()
