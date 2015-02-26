#!/usr/bin/env python
# coding: utf-8
#
# Joint databases
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

from __future__ import print_function, absolute_import
from ekklesia.backends import api_defaults
from ekklesia.backends.members import MemberDatabase, members_spec
from ekklesia.backends.invitations import InvitationDatabase, invitations_spec
from ekklesia.mail import gpg_defaults, smtp_defaults

class MemberInvDatabase(MemberDatabase,InvitationDatabase):

    def __init__(self, *args, **kwargs):
        super(MemberInvDatabase,self).__init__(*args, **kwargs)

    def configure(self,config={},gpgconfig=gpg_defaults,memberconfig=api_defaults,
        invconfig=api_defaults, smtpconfig=smtp_defaults):
        from ekklesia.backends import APIConfig, spec_defaults
        if not 'export_invite' in config:
            config['export_invite'] = False # default
        if not 'invite_import' in config:
            config['invite_import'] = ['id','member_id','code','status','sent','lastchange']
        super(MemberInvDatabase,self).configure(config,apiconfig=memberconfig,
            gpgconfig=gpgconfig)
        api = api_defaults.copy()
        api.update(invconfig)
        self.invite_api = APIConfig(**api)
        self.member_class = None # set later
        defaults = spec_defaults(members_spec)['members']
        defaults.update(spec_defaults(invitations_spec)['invitations'])
        for key in defaults.keys():
            setattr(self,key,config.get(key,defaults[key]))
        return self

    def init_parser_main(self,name,description):
        parser, subparsers = MemberDatabase.init_parser_main(self,name,description)
        parser.add_argument("-c", "--codes", action="store_true", default=False, help="work with invitation codes")
        return parser, subparsers

    def init_parser_init(self,subparsers):
        parser = MemberDatabase.init_parser_init(self,subparsers)
        parser.add_argument("-c","--codes",metavar='CODES',help='file with initial invite codes')
        return parser

    def init_parser_import(self,subparsers, withfile=True):
        parser = super(MemberInvDatabase,self).init_parser_import(subparsers,withfile=False)
        parser.add_argument("input",nargs="+",help='input file(s) with members[,departments] or codes')
        return parser

    def init_parser_export(self,subparsers):
        parser = super(MemberInvDatabase,self).init_parser_export(subparsers,withfile=False)
        parser.add_argument("output",nargs='+',help='output files for members,departments and invitations')
        return parser

    def init_parsers(self,name,description):
        parser, subparsers = InvitationDatabase.init_parsers(self,name,description)
        return parser, subparsers

    def declare(self,reflect=True):
        MemberDatabase.declare(self,reflect)
        self.member_class = self.Member
        InvitationDatabase.declare(self,reflect)

    def reflect_classes(self):
        MemberDatabase.reflect_classes(self)
        InvitationDatabase.reflect_classes(self)

    def email_change(self,member,data):
        from ekklesia.backends.invitations import IStatusType, ISentStatusType
        inv = member.invitation
        if not inv: return
        if not data['email']:
            self.info("scheduling invitation for uuid '%s' for deletion", inv.uuid)
            inv.delete()
        elif inv.status==IStatusType.uploaded and inv.sent==ISentStatusType.sent:
            inv.reset()

    def delete_member(self,member):
        super(MemberInvDatabase,self).delete_member(member)
        inv = member.invitation
        if inv: inv.delete()

    def process_update(self,msg,input=None,output=None):
        update = MemberDatabase.process_update(self,msg,input,output)
        return InvitationDatabase.process_update(self,msg,input,output) or update

    def run(self, args=None): # pragma: no cover
        from ekklesia.data import special_openwith
        from ekklesia.backends import api_spec, dummy_context, session_context
        from ekklesia.mail import gpg_spec, smtp_spec
        from sqlalchemy import create_engine
        args, parser = self.init_run('joint',
            'synchronization of member databases and invitations',args)
        apis = api_spec('member_api')+api_spec('invitation_api')
        spec = members_spec+invitations_spec+gpg_spec+smtp_spec+apis
        config = self.get_configuration(spec,args,'joint.ini')
        jconfig = {}
        jconfig.update(config['members'])
        jconfig.update(config['invitations'])
        self.configure(config=jconfig,
            memberconfig=config['member_api'],invconfig=config['invitation_api'],
            gpgconfig=config['gnupg'],smtpconfig=config['smtp'])
        self.init_gnupg()
        if args.command=='push' and args.daemon:
            daemon = self.prepare_daemon(args.pid)
        else: daemon = dummy_context()
        with daemon, session_context(self):
            engine = create_engine(self.database,echo=False) #, echo=self.debugging
            if args.command == 'init':
                self.open_db(engine,mode='create')
                self.info('database intialized')
                if args.initial:
                    with special_openwith(args.initial, 'r') as f:
                        self.import_members(f,allfields=True)
                if args.codes:
                    with special_openwith(args.codes, 'r') as f:
                        self.import_invitations(f,allfields=True)
                return
            elif args.command == 'drop':
                self.info('deleting database')
                self.open_db(engine,mode='dropall' if args.all else 'drop')
                return
            self.open_db(engine,mode='open')
            if args.command == 'import':
                if args.codes:
                    assert len(args.input) == 1, "invalid number of input arguments"
                    self.run_import_invitations(args, args.input[0])
                else:
                    self.run_import_members(args)
            elif args.command == 'export':
                if args.codes:
                    assert len(args.output) == 1, "invalid number of output arguments"
                    self.run_export_invitations(args, args.output[0])
                else:
                    self.run_export_members(args)
            elif args.command == 'push':
                if not args.daemon:
                    import signal
                    signal.signal(signal.SIGHUP, self.terminate)
                    signal.signal(signal.SIGINT, self.terminate)
                assert not self.member_api.sign or self.gpgconfig['sender'], 'sender for signing missing'
                if args.dryrun: self.info('simulating push')
                self.push_sync(upload=args.upload,delay=args.wait,dryrun=args.dryrun)
            elif args.command == 'sync':
                if args.codes:
                    self.run_sync_invitations(args)
                else:
                    self.run_sync_members(args)
            elif args.command == 'reset':
                self.run_reset_invitations(args)
            elif args.command == 'send':
                if args.dryrun: self.info('simulating send')
                self.send_invitations(dryrun=args.dryrun)

def main_func(): # pragma: no cover
    MemberInvDatabase().run()

if __name__ == "__main__": main_func()
