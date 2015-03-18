# -*- coding: utf-8 -*-
#
# Email background tasks
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

from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import ugettext as _
from django.conf import settings
from ekklesia.data import dummy_context
from optparse import make_option
import logging
log = logging.getLogger(__name__)

class Command(BaseCommand):

    args = '[options]'
    help = 'perform email background tasks'

    option_list = BaseCommand.option_list + (
        make_option("-i", "--incoming", action="store_true", default=False, help="process incoming messages"),
        make_option("-o", "--outgoing", action="store_true", default=False, help="process outgoing messages"),
        make_option("-r", "--register", action="store_true", default=False, help="process key registration"),
        make_option("-c", "--crypto", action="store_true", default=False, help="process crypto tasks"),
        make_option("-1", "--once", action="store_true", dest="once", default=False, help="run only one pass"),
        make_option("-d", "--daemon", action="store_true", default=False, help="run as daemon in background"),
        make_option("-n", "--dry-run", action="store_true", dest="dryrun", default=False, help="only simulate action"),
        make_option("-s", "--no-send", action="store_true", default=False, help="don't send emails"),
        make_option("-p", "--period", metavar='SECONDS',type=int, default=30,help='periodic starts every x seconds (default 30)'),
        make_option("-P", "--pid", metavar='PIDFILE', help='file to write daemon pid to'),
        )

    def terminate(self, signal, frame): # pragma: no cover
        "signal handler for push termination"
        log.info('terminating: signal %s',signal)
        if self.connection: self.connection.close()
        self.terminated = True

    def handle(self, *args, **options):
        import signal, os

        if options['daemon']:
            import daemon, daemon.pidfile
            pidfile = daemon.pidfile.PIDLockFile(options['pid']) if options['pid'] else None
            context = daemon.DaemonContext(pidfile=pidfile, working_directory=os.getcwd())
            context.signal_map = {signal.SIGTERM: self.terminate, signal.SIGHUP: self.terminate}
            context.files_preserve = []
            for handler in log.handlers:
                if not isinstance(handler,logging.StreamHandler): continue
                context.files_preserve.append(handler.stream)
            daemon = context
        else:
            signal.signal(signal.SIGHUP, self.terminate)
            signal.signal(signal.SIGINT, self.terminate)
            daemon = dummy_context()
        self.connection = None
        self.terminated = False
        with daemon:
            self.worker(register=options['register'],incoming=options['incoming'],
                outgoing=options['outgoing'],crypto=options['crypto'],
                period=options['period'],once=options['once'],
                send=not options['no_send'],dryrun=options['dryrun'])

    def worker(self,incoming=False,outgoing=False,register=False,crypto=False,
        once=False,dryrun=False,send=True,period=0):
        import time, celery, socket, ssl
        from kombu import Connection, Exchange, Queue, Producer, Consumer
        from idapi.mails import save_mail, send_mails, get_mails, process_crypto, process_register

        if not (incoming or outgoing or register or crypto):
            raise CommandError('nothing to do')
        conn = dummy_context()
        if settings.BROKER_URL and incoming:
            if settings.USE_CELERY:
                conn = celery.current_app.pool.acquire(timeout=1)
            else:
                conn = Connection(settings.BROKER_URL,ssl=settings.BROKER_USE_SSL)

        imap, smtp = {}, {} # connection cache
        last_time = 0
        with conn as conn:
            self.connection = conn
            while not self.terminated:
                towait = period - (time.time() - last_time)
                if towait>0: time.sleep(towait)
                last_time = time.time()
                if incoming:
                    get_mails(joint=True,connections=imap,notify=conn)
                if outgoing:
                    send_mails(joint=True,connections=smtp)
                if register:
                    process_register()
                if crypto:
                    process_crypto(notify=conn)
                if once: break
