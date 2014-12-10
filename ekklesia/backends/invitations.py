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
fields (format: invitation 1.0):
uuid    - unique member id (UUID max.36)
email   - email adress (if not joint db)
code - unique invitation code (max.36)
status  - new, uploaded, failed, registered, deleted
extra for sync:
echo    - return in response (optional)
check_email - email to check, return 0/1 response if not empty (optional)

internal:
sent    - 1=ok, 0=not send, -1=failed, -2=retry
#senddate - when code email was sent, or null

import fields: uuid(,email if not joint)[,code]
export fields: uuid,code(,email if not joint)
sync download: uuid,status[,check_email][,echo]
sync upload: uuid,status,code[,check_email][,echo]
 echo or check_email if in download and enabled

reset data: simple linewise list of emails or uuids

import:
independent: members -> export deleted or not registered, import & gen codes or delete, sync status
joint: members -> set status for registered, gen codes for non-reg, sync status
memberdb exports all uuids+emails
import uuid[,email] - email if not joint
if uuid not found, ignore
if email is empty -> delete code

sync:
download: uuid,status
 registered and failed uuids
upload: uuid,status,code
 if implicit delete: non-uploaded invs are deleted
 status: new (or response to failed),deleted,registered (response to registered)
 if new, create/overwrite inv
 if deleted/registered, delete inv

states: updated only in reaction to confirmation (command -> confirm -> next cmd)
1. import from memberdb: new, unsent, generate code
2. upload to idserver: new->new
3. download from idserver: new -> uploaded, unsent (otherwise not ready for sending)
4. send mail: uploaded,sent (or retry until sent, failed->fix email?new code)
5. reset: set to 1.
6. download:
 failed on failed,sent -> new,unsent (1.)
 failed on uploaded -> failed,unsent
 registered on uploaded -> registered,unsent
7. send confirmation/rejection, failed->1., registered->registered,sent
8. upload: registered or deleted ->delete
 failed,unsent->failed

state transitions:
backend,idserver -> target
new,-         -> idserver:new
new,new       -> idserver:new
new,new       -> backend:uploaded
-,any         -> backend:deleted,error
uploaded,new /-> idserver
uploaded,new  -> backend:uploaded
uploaded,reging-> backend:uploaded
uploaded,reg  -> backend:registered
reg,reg       -> backend:reg
reg,reg       -> idserver:delete
uploaded,fail -> backend:fail
fail,fail     -> backend:fail
fail,fail     -> idserver:delete (or new,new)
fail,-        -> backend:new (check if fail not downloaded)

requirements: Python >=2.7, sqlalchemy, gnupg, requests
"""

from __future__ import print_function, absolute_import
from ekklesia.backends import (AbstractDatabase, APIConfig, spec_defaults, api_defaults,
    FileMissingWarning, UnknownFieldsWarning, DeclEnum, EnumSymbol)
from ekklesia.mail import gpg_defaults, smtp_defaults
from ekklesia import FormattedWarning

class StatusType(DeclEnum):
    deleted = EnumSymbol('deleted')
    new = EnumSymbol('new')
    uploaded = EnumSymbol('uploaded')
    failed = EnumSymbol('failed')
    registered = EnumSymbol('registered')

class SentStatusType(DeclEnum):
    unsent = EnumSymbol('unsent')
    sent = EnumSymbol('sent')
    retry = EnumSymbol('retry')
    failed = EnumSymbol('failed')

invitations_spec ='''
[invitations]
invite_table = string(default='invitations')
invite_import = string_list(default=list('uuid','email','code','status','sent','lastchange'))
invite_check_email = string # allow check_email, if empty disabled
invite_subject = string(default='Invitation Code')
invite_body = string(default="""Dear member,\\nYou're welcome to sign up for Ekklesia.\\nPlease your following personal link to sign up\\n<%s>\\nWarning: Do not forward or show this message to anyone else.\\nOtherwise someone else sign up in your name with this link.\\nThank you""")
registered_subject = string(default='Registration successful')
registered_body = string(default="Your account has been successfully registered")
failed_subject = string(default='Registration failed')
failed_body = string(default="Your account registration has failed. You're going to receive another invitation soon.")
invite_url = string(default='https://localhost/register?code=%s')
invite_sign = boolean(default=True) # sign invitation emails
invite_notify = boolean(default=True) # send confirmation after registration
'''

class InvitationDatabase(AbstractDatabase):
    version = [1,0]
    
    def __init__(self,config={},gpgconfig=gpg_defaults,apiconfig=api_defaults,smtpconfig=smtp_defaults,logger=None):
        super(InvitationDatabase,self).__init__(config,gpgconfig,logger)
        api = api_defaults.copy()
        api.update(apiconfig)
        self.invite_api = APIConfig(**api)
        self.smtpconfig = smtpconfig
        self.member_class = None # integrated with Member table
        assert self.version[0]<=1, 'invalid version'
        defaults = spec_defaults(invitations_spec)['invitations']
        for key in defaults.keys():
            setattr(self,key,config.get(key,defaults[key]))

    def init_parser_reset(self,subparsers):
        parser = subparsers.add_parser('reset', help='reset sent status or invite codes')
        parser.add_argument("-i", "--invite", action="store_true", default=False, help="reset invite codes, otherwise only sent status")
        parser.add_argument("-u", "--uuid", action="store_true", default=False, help="file contains uuids, otherwise emails")
        parser.add_argument("file",help='file with emails/uuids')
        return parser

    def init_parser_send(self,subparsers):
        parser = subparsers.add_parser('send', help='send emails to members')
        return parser

    def init_parsers(self,name,description):
        parser, subparsers = self.init_parser_main(name,description)
        self.init_parser_init(subparsers)
        self.init_parser_import(subparsers)
        self.init_parser_export(subparsers)
        self.init_parser_sync(subparsers)
        self.init_parser_reset(subparsers)
        self.init_parser_send(subparsers)
        return parser, subparsers

    def declare(self,reflect=True):
        from sqlalchemy import (Table, Column, ForeignKey,
            Sequence, Integer, String, Boolean, DateTime, func)
        from sqlalchemy.orm import relationship, backref
        from ekklesia.data import init_object, repr_object

        class Invitation(self.Base):
            if not reflect:
                __tablename__ = self.invite_table
                if self.member_class:
                    id = Column(Integer, Sequence('id_seq',optional=True), primary_key=True)
                    member_id = Column(Integer, ForeignKey(self.member_class.id,name='member_fk'), nullable=False)
                else:
                    uuid = Column(String(36), primary_key=True)
                    email = Column(String(254), nullable=False, unique=True, index=True)
                code = Column(String(36), nullable=False, unique=True)
                status = Column(StatusType.db_type(), nullable=False, default=StatusType.new)
                sent = Column(SentStatusType.db_type(), nullable=False, default=SentStatusType.unsent)
                if 'lastchange' in self.invite_import:
                    lastchange = Column(DateTime, nullable=True, default=func.now())
            else:
                __table__ = Table(self.invite_table, self.Base.metadata)
                if 'invitations' in self.column_map:
                    __mapper_args__ = {'include_properties' : list(self.column_map['invitations'].keys()) }
            if self.member_class:
                member = relationship(self.member_class, backref=backref("invitation", uselist=False))

            def __init__(inv, **kwargs):
                from uuid import uuid4
                if 'uuid' in kwargs: assert kwargs['uuid'], "uuid missing"
                if 'code' in kwargs: value = kwargs['code']
                else: value = uuid4()
                kwargs['code'] = str(value)
                init_object(inv,**kwargs)

            def reset(inv):
                from uuid import uuid4
                import datetime
                inv.status = StatusType.new
                inv.sent = SentStatusType.unsent
                inv.code = str(uuid4())
                if 'lastchange' in self.invite_import:
                    data['lastchange'] = datetime.utcnow()

            def __repr__(inv):
                return repr_object(inv,self.invite_columns)

        self.Invitation = Invitation

    def reflect_classes(self):
        from ekklesia.backends import reflect_class
        self.invite_columns, self.invite_types = reflect_class(self.Invitation)

    def import_invitations(self,input,decrypt=False,verify=False,
            allfields=False,dryrun=False,format='csv'):
        from ekklesia.data import DataTable
        from datetime import datetime
        session = self.session
        Invitation = self.Invitation
        membercls = self.member_class
        columns = self.invite_columns
        if membercls: columns.append('uuid')
        if allfields: reqcolumns = columns
        elif membercls: reqcolumns.append('uuid')
        else: reqcolumns = ['uuid','email']
        reader = DataTable(columns,coltypes=self.invite_types,required=reqcolumns,
            dataformat='invitation',fileformat=format,version=self.version,gpg=self.gpg)
        reader.open(input,'r',encrypt=decrypt,sign=verify)
        columns, tmp = reader.get_columns()
        recordchange = 'status' in columns and not 'lastchange' in columns
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
                    if member.invitation:
                        self.info("scheduling invitation for uuid '%s' for deletion", member.uuid)
                        if not dryrun:
                            member.invitation.status = StatusType.deleted
                            member.invitation.lastchange = datetime.utcnow()
                    continue
                count += 1
                if dryrun: continue
                if member.invitation is None: # create a new invitation
                    session.add(Invitation(member=member,**data)) #new
                else:
                    if recordchange and data['status']!=member.invitation.status:
                        data['lastchange'] = datetime.utcnow()
                    member.invitation.__init__(**data) #update inv
            else:
                inv = iquery.filter_by(uuid=uuid).first()
                if not data['email']: # email removed, disable invitation
                    if inv is None:
                        self.warn("uuid %s not found" % uuid)
                        continue
                    if inv.status == StatusType.deleted: continue
                    self.info("scheduling invitation for uuid '%s' for deletion", inv.uuid)
                    if not dryrun:
                        inv.status = StatusType.deleted
                        inv.lastchange = datetime.utcnow()
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
                    needreset = not allfields and inv.status==StatusType.uploaded and \
                         inv.sent==SentStatusType.sent and 'email' in data and data['email']!=inv.email and \
                         (not 'code' in data or data['code']==inv.code)
                    if not needreset and recordchange and data['status'] != inv.status:
                        data['lastchange'] = datetime.utcnow()
                    inv.__init__(**data) #update inv
                    if needreset: inv.reset()
                else:
                    session.add(Invitation(**data)) #new
        self.info('%i imported invitations', count)
        if not dryrun: session.commit()

    def export_invitations(self,output,allfields=False,encrypt=None,sign=False,format='csv'):
        from ekklesia.data import DataTable
        session = self.session
        Invitation = self.Invitation
        membercls = self.member_class
        if allfields:
            columns = self.invite_columns
            if membercls: columns = ['uuid']+columns
        else:  # restricted
            columns = ['uuid','code']
            if not membercls: columns.append('email')
        if encrypt: encrypt = [encrypt]
        writer = DataTable(columns,coltypes=self.invite_types,gpg=self.gpg,
            dataformat='invitation',fileformat=format,version=self.version)
        writer.open(output,'w',encrypt=encrypt,sign=sign)
        count = 0
        for inv in session.query(Invitation).order_by(Invitation.id if membercls else Invitation.uuid):
            extra = {}
            if membercls: extra['uuid'] = inv.member.uuid
            writer.write(inv,extra)
            count += 1
        writer.close()
        self.info('%i exported invitations', count)

    def sync_invitations(self,download=True,upload=True,dryrun=False,input=None,output=None):
        # input/output=local streams
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
            if not input:
                resp = api.get(self.invite_api.url)
                assert resp.status_code == requests.codes.ok, 'cannot download used invite codes'
                input = resp.json()
            columns = ['uuid','status','echo']
            if check_email: columns.append(check_email)
            reader = DataTable(columns,coltypes=self.invite_types,required=('uuid','status'),gpg=self.gpg,
                dataformat='invitation',fileformat=self.invite_api.format,version=self.version)
            reader.open(input,'r',encrypt=self.invite_api.encrypt,sign=self.invite_api.receiver)
            rcolumns,unknown = reader.get_columns()
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
                if not status in ('new','registered','failed'):
                    self.warn("invalid status %s for %s" % (status,uuid))
                    continue
                inv = query.filter_by(uuid=uuid).first()
                extra = {}
                if not inv:
                    self.error("member %s is unknown" % data['uuid'])
                    if check_email in columns and data[check_email]:
                        extra[check_email] = False
                    extra['uuid'] = uuid
                    writer.write(Invitation(status=StatusType.deleted,code=''),extra)
                    continue
                if membercls:
                    inv = inv.invitation
                    if not inv: # FIXME: generate?
                        self.error("missing code for %s" % uuid)
                        continue
                status = data['status'] # compare status
                # new on new -> uploaded
                # new on uploaded -> ignore
                # registered/failed on uploaded -> registered/failed
                # registered/failed on same -> ignore
                # deleted on failed -> new
                if status == StatusType.new:
                    if inv.status == StatusType.new:
                        inv.status = StatusType.uploaded
                        inv.sent = SentStatusType.unsent
                    elif inv.status != StatusType.uploaded:
                        self.error("bad status %s for uuid %s, current %s",
                             status,data['uuid'],inv.status)
                        continue
                elif inv.status == StatusType.uploaded: # status in registered/failed
                    inv.status = status # upload confirmed or failed registration
                    inv.sent = SentStatusType.unsent
                elif status != inv.status:
                    self.error("bad status %s for uuid %s, current %s",
                        status, data['uuid'],inv.status)
                    continue
                if upload and (status != StatusType.new or reply): # write response for uploaded
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
        query = session.query(Invitation).filter_by(status=str(StatusType.failed),
            sent=str(SentStatusType.sent))
        for inv in query:
            extra = {}
            if membercls: uuid = inv.member.uuid
            else: uuid = inv.uuid
            if uuid in seen: continue # already replied
            inv.reset()
            count += 1
        self.info('%i codes resetted', count)
        if not dryrun: session.commit()
        # append new invitations
        count = 0
        query = session.query(Invitation).filter_by(status=str(StatusType.new))
        for inv in query:
            extra = {}
            if membercls:
                uuid = inv.member.uuid
                extra['uuid'] = uuid
            else: uuid = inv.uuid
            writer.write(inv,extra)
            count += 1
        writer.close()
        self.info('%i new codes uploaded', count)
        if output:
            json.dump(out,output)
        elif not dryrun:
            r = api.post(self.invite_api.url,json=out)
            assert r.status_code == requests.codes.ok, 'cannot upload data'
    
    def reset_invitations(self,input,code=False,uuids=False,dryrun=False):
        session = self.session
        Invitation = self.Invitation
        membercls = self.member_class
        count = 0
        if membercls: query = session.query(Invitation,membercls)
        else: query = session.query(Invitation)
        for line in input:
            line = line.rstrip()
            if uuids: inv = query.filter_by(uuid=line).first()
            else: inv = query.filter_by(email=line).first()
            if inv is None:
                self.error('member %s not found' % line)
                continue
            if code:
                from uuid import uuid4
                if inv.status==StatusType.registered:
                    self.error('member %s has already used the code' % line)
                    continue
                if inv.status==StatusType.deleted:
                    self.error('member %s is already deactivated' % line)
                    continue
                count +=1
                if dryrun: continue
                inv.reset()
            else:
                count +=1
                if not dryrun: inv.sent = SentStatusType.unsent # resent
        self.info('%i resets', count)
        if not dryrun: session.commit()

    def create_mail(self,status,inv,sender,email,code=None):
        from kryptomime import create_mail
        if status == StatusType.uploaded:
            link = self.invite_url % inv.code
            subject, body = self.invite_subject,self.invite_body % link
        elif status == StatusType.registered:
            subject, body = self.registered_subject, self.registered_body
        else: # status == StatusType.failed:
            subject, body = self.failed_subject, self.failed_body
        return create_mail(sender,email,subject,body)

    def send_invitations(self,dryrun=False,debug_smtp=None):
        from datetime import datetime
        from ekklesia.mail import smtp_init
        from sqlalchemy import or_
        import smtplib
        session = self.session
        Invitation = self.Invitation
        if debug_smtp: smtp = debug_smtp
        else:
            smtp = smtp_init(self.smtpconfig)
            smtp.open()
        sender = self.gpgconfig['sender']
        query = session.query(Invitation)
        query = query.filter(Invitation.status.in_([StatusType.uploaded,StatusType.registered,StatusType.failed]))
        query = query.filter(Invitation.sent.in_([SentStatusType.unsent,SentStatusType.retry]))
        count = 0
        for inv in query:
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
                    inv.sent = SentStatusType.sent
                except smtplib.SMTPRecipientsRefused:
                    inv.sent = SentStatusType.failed # failed
                except (smtplib.SMTPDataError,smtplib.SMTPSenderRefused,smtplib.SMTPHeloError):
                    inv.sent = SentStatusType.retry # retry
                if 'lastchange' in self.invite_import:
                    inv.lastchange = datetime.now()
            count +=1
        if not dryrun: session.commit()
        if not debug_smtp: smtp.close()
        self.info('%i emails successfully sent', count)

    def run(self, args=None): # pragma: no cover
        from ekklesia.data import special_openwith, special_open
        args, engine, parser = self.init_run('invitations','invitation script for members',args)
        try:
            if args.command == 'init':
                self.open_db(engine,mode='create')
                self.info('database intialized')
                if args.initial:
                    with special_openwith(args.initial, 'r') as f:
                        self.import_invitations(f,allfields=True)
                return
            elif args.command == 'drop':
                self.info('deleting database')
                self.open_db(engine,mode='drop')
                return
            self.open_db(engine,mode='open')
            if args.command == 'import':
                if args.dryrun: self.info('simulating import')
                with special_openwith(args.file, 'r') as f:
                    self.import_invitations(f,decrypt=args.decrypt,verify=args.verify,
                        dryrun=args.dryrun,allfields=args.all)
            elif args.command == 'export':
                with special_openwith(args.file, 'w') as f:
                    if args.encrypt: args.encrypt = self.gpgconfig['sender'] # to self
                    self.export_invitations(f,encrypt=args.encrypt,
                        sign=args.sign,allfields=args.all)
            elif args.command == 'sync':
                assert not self.invite_api.sign or self.gpgconfig['sender'], 'sender for signing missing'
                if args.output: assert len(args.output)==1, "only one output file expected"
                if args.dryrun: self.info('simulating sync')
                input = special_open(args.input,'r') if args.input else None
                output = special_open(args.output[0],'w') if args.output else None
                self.sync_invitations(download=args.download,upload=args.upload,
                    input=input,output=output,dryrun=args.dryrun)
            elif args.command == 'reset':
                if args.dryrun: self.info('simulating reset')
                with special_openwith(args.file, 'r') as f:
                    self.reset_invitations(f,code=args.invite,uuids=args.uuid,dryrun=args.dryrun)
            elif args.command == 'send':
                if args.dryrun: self.info('simulating send')
                self.send_invitations(dryrun=args.dryrun)
        except:
            self.exception('')
        finally:
            self.session.close()

def main_func(): # pragma: no cover
    from ekklesia.backends import api_spec
    from ekklesia.mail import gpg_spec, smtp_spec
    import os, configobj, validate

    spec = invitations_spec+gpg_spec+smtp_spec+api_spec
    config = configobj.ConfigObj('invitations.ini', configspec=spec.split('\n'),encoding='UTF8')
    config.validate(validate.Validator())
    if not config['gnupg']['home']:
        config['gnupg']['home'] = os.path.join(os.getenv('HOME'),'.gnupg')
    else:
        config['gnupg']['home'] = os.path.expanduser(config['gnupg']['home'])
    InvitationDatabase(config=config['invitations'],gpgconfig=config['gnupg'],
        apiconfig=config['api'],smtpconfig=config['smtp']).run()

if __name__ == "__main__": main_func()
