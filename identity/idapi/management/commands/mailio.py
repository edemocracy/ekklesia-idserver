# -*- coding: utf-8 -*-
#
# mail input/output
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

from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import ugettext as _
from django.conf import settings
from optparse import make_option

worker_work = False # global var for signal

def handler(signum, frame):
    print('Signal handler called with signal', signum, frame.f_locals)
    print('finishing current action')
    global worker_work
    worker_work = False

class Command(BaseCommand):

    args = '[options]'
    help = 'perform email background tasks'

    option_list = BaseCommand.option_list + (
        make_option("-i", "--incoming", action="store_true", default=True, help="process incoming messages"),
        make_option("-o", "--outgoing", action="store_true", default=False, help="process outgoing messages"),
        make_option("-r", "--register", action="store_true", default=True, help="process key registration"),
        make_option("-c", "--crypto", action="store_true", default=False, help="process crypto tasks"),
        make_option("-1", "--once", action="store_true", dest="once", default=False, help="run only one pass"),
        make_option("-d", "--daemon", action="store_true", default=False, help="run as daemon in background"),
        make_option("-n", "--dry-run", action="store_true", dest="dryrun", default=False, help="only simulate action"),
        make_option("-s", "--send", action="store_true", default=True, help="send emails"),
        make_option("-p", "--period", metavar='SECONDS',type=int, default=0,help='periodic starts every x seconds'),
        )

    def handle(self, *args, **options):
        import signal, time
        global worker_work
        print args, options
        if options['daemon']:
            import daemoncmd
            daemoncmd.daemonize()
        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGHUP, handler)
        signal.signal(signal.SIGINT, handler) # keyboard
        worker_work = True

        self.worker(register=options['register'],incoming=options['incoming'],
            outgoing=options['outgoing'],crypto=options['crypto'],
            period=options['period'],once=options['once'],
            send=options['send'],daemon=options['daemon'],dryrun=options['dryrun'])

    def worker(self,incoming=False,outgoing=False,register=False,crypto=False,
        daemon=False,once=False,dryrun=False,send=True,period=0):
        import time
        from idapi.mails import save_mail, send_mails, get_mails, process_crypto, process_register
        global worker_work

        imap, smtp = {}, {} # connection cache
        last_time = 0
        while worker_work:
            towait = period - (time.time() - last_time)
            if towait>0 : time.sleep(towait)
            last_time = time.time()
            if incoming:
                send_mails(joint=True,connections=imaps)
            if outgoing:
                send_mails(joint=True,connections=smtp)
            if register:
                process_register()
            if crypto:
                process_crypto()
            if once: break
