# -*- coding: utf-8 -*-
#
# Store email
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
import email.utils

def findkey(gpg,keyid):
    for key in gpg.list_keys():
        for uid in key['uids']:
            if keyid == email.utils.parseaddr(uid)[1]:
                return key['fingerprint']
    return None
    
class Command(BaseCommand):

    args = '[options] [keyid]'
    help = 'register key'

    option_list = BaseCommand.option_list + (
        make_option("-d", "--download", action="store_true", default=False,
            help="download from keyserver"),
        make_option("-g", "--gnupg", action="store_true", default=False,
            help="import from gnupg"),
        make_option("-f", "--file", help="ready input from file"),
        make_option("-u", "--user", help="only accept key for this user"),
        make_option("-t", "--trust", default='trusted', help="trust level (unconfirmed,confirmed,trusted)"),
        make_option("-H", "--home", default=None, help="gnupg home for import"),
        make_option("-s", "--server", default='hkp://pgp.mit.edu', help="keyserver"),
        )

    def handle(self, *args, **options):
        from accounts.models import Account
        from idapi.models import PublicKey
        from idapi.mails import gnupg_init, gnupg_import_init, update_keyrings
        from tempfile import mkdtemp
        from shutil import rmtree
        import os, sys, email.utils

        if len(args)>1:
            raise CommandError('invalid number of arguments')
        keyid = args[0] if len(args)==1 else None
        if options['user']:
            try: user = Account.objects.get(username=options['user'])
            except Account.DoesNotExist:
                raise CommandError('user not found')
            if not keyid: keyid = user.email
        try: trust = PublicKey.TRUST_LUT[options['trust']]
        except KeyError: raise CommandError('invalid trust level')
        try: # first try to import to temporary keyring
            tmpdir = mkdtemp()
            gpg = gnupg_init(tmpdir)
            if options['file']: # read from file, possibly multiple
                if not os.path.exists(options['file']):
                    raise CommandError('input file does not exist')
                key = open(options['file'],'rt').read()
            elif options['download']:
                if not keyid: raise CommandError('keyid is required')
            elif not keyid: # single key form stdin
                key = sys.stdin.read()
            else:
                # import form gnupg home
                gpgimport = gnupg_import_init(home=options['home'])
                if '@' in keyid: # email
                    keyid = findkey(gpgimport,keyid)
                    if not keyid: raise CommandError('keyid not found')
                key = gpgimport.export_keys(keyid)
            if keyid and options['download']:
                res = gpg.recv_keys(keyid,keyserver=options['server'])
            else:
                if not key: raise CommandError('input is missing')
                res = gpg.import_keys(key)
            if not len(res.fingerprints):
                raise CommandError('could not import key')
            multikey = keyid and options['file']
            if not multikey:
                if len(res.fingerprints)>1:
                    raise CommandError('more than one key found')
                fingerprint = res.fingerprints[0]
            else:
                # for multikey look up single fingerprint
                fingerprint = None
            for pkey in gpg.list_keys():
                uids = [email.utils.parseaddr(uid)[1] for uid in pkey['uids']]
                if multikey:
                    if '@' in keyid:
                        if not keyid in uids: continue
                    elif not keyid in (pkey['keyid'],pkey['fingerprint']): continue
                    fingerprint = pkey['fingerprint']
                expires = pkey['expires']
                break
            if multikey:
                if not fingerprint: raise CommandError('could not find keyid')
            print 'importing', fingerprint
            if expires:
                from datetime import datetime
                import time
                from django.utils.timezone import make_aware, utc
                if 'T' in expires:
                    expires = datetime(*time.strptime(data,"%Y%m%dT%H%M%S")[0:6])
                else:
                    expires = datetime.utcfromtimestamp(int(expires))
                expires = make_aware(expires,utc)
            key = gpg.export_keys(fingerprint)
        finally:
            rmtree(tmpdir)
        # keyid and user match?
        if options['user']:
            if not user.email in uids:
                raise CommandError('key does not match user email')
        else:
            query = Account.objects.filter(email__in=uids)
            count = query.count()
            if not count:
                raise CommandError('key does not match any user')
            if count>1:
                raise CommandError('key matches multiple users')
            user = query.first()
        active = user.publickeys.filter(active=True,keytype=PublicKey.PGP).first()
        if active and active.fingerprint != fingerprint:
            # deactivate old
            active.active = False
            active.save(update_fields=('active',))
        userkey = user.publickeys.filter(fingerprint=fingerprint, keytype=PublicKey.PGP).first()
        if userkey:
            userkey.data['keydata'] = key
            userkey.data['identities'] = uids
            userkey.trust = trust
            userkey.expires = expires
            userkey.active = True
            userkey.save(update_fields=('active','data','trust','expires'))
        else:
            user.publickeys.create(active=True,fingerprint=fingerprint,keytype=PublicKey.PGP,
                expires=expires, trust=trust,data=dict(keydata=key,identites=uids))
        if trust != PublicKey.UNCONFIRMED:
            update_keyrings()
