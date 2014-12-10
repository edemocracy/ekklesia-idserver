#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# based on kryptomime tests
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
from pytest import fixture

sender='foo@localhost'
passphrase='mysecret'
receiver='bar@localhost'
third='fnord@localhost'

def pytest_addoption(parser):
    parser.addoption("--generate", action="store_true", help="generate PGP keys")
    parser.addoption("--gpglog", action="store_true", help="verbose gnupg output")

@fixture(scope='module')
def keys(request):
    import os, gnupg
    from kryptomime import GPGMIME
    from kryptomime.pgp import find_gnupg_key
    from ekklesia.data import tmpfname
    #generate = verbose = False
    generate = request.config.getoption('generate',False)
    verbose = request.config.getoption('gpglog',False)
    if verbose: gnupg._logger.create_logger(10)
    if generate:
        keyrings = [tmpfname() for i in range(3)]
        secrings = [tmpfname() for i in range(3)]
    else:
        home = os.path.dirname(os.path.abspath(__file__))
        keyrings = [os.path.join(home,'keyring%i.gpg'%i) for i in range(3)]
        secrings = [os.path.join(home,'secring%i.gpg'%i) for i in range(3)]
        pubring = os.path.join(home,'pubring.gpg')
    keygen = generate
    if not keygen:
        for fname in keyrings+secrings:
            if os.path.exists(fname): continue
            keygen = True
            break
    if keygen:
        for fname in keyrings+secrings:
            if os.path.exists(fname): os.unlink(fname)
    gpg1 = gnupg.GPG(keyring=keyrings[0],secring=secrings[0],verbose=verbose)
    gpg2 = gnupg.GPG(keyring=keyrings[1],secring=secrings[1],verbose=verbose)
    gpg3 = gnupg.GPG(keyring=keyrings[2],secring=secrings[2],verbose=verbose)
    if keygen:
        key1 = gpg1.gen_key(gpg1.gen_key_input(name_email=sender,key_length=1024,passphrase=passphrase)).fingerprint
        key2 = gpg2.gen_key(gpg2.gen_key_input(name_email=receiver,key_length=1024)).fingerprint
        key3 = gpg3.gen_key(gpg3.gen_key_input(name_email=third,key_length=1024)).fingerprint
    else:
        key1 = find_gnupg_key(gpg1,sender)
        key2 = find_gnupg_key(gpg2,receiver)
        key3 = find_gnupg_key(gpg3,third)
    pubkey1= gpg1.export_keys(key1)
    pubkey2= gpg2.export_keys(key2)
    pubkey3= gpg3.export_keys(key3)
    if not generate and not os.path.exists(pubring):
        gpg = gnupg.GPG(keyring=pubring,verbose=verbose)
        gpg.import_keys(pubkey1)
        gpg.import_keys(pubkey2)
        gpg.import_keys(pubkey2)
    def fin():
        for tmp in keyrings+secrings: os.unlink(tmp)
    if generate: request.addfinalizer(fin)
    return {'gpg1':gpg1, 'gpg2':gpg2, 'gpg3':gpg3, 'pubkey1':pubkey1, 'pubkey2':pubkey2, 'pubkey3':pubkey3, 'secrings':secrings}

@fixture(scope='module')
def gpgsender(keys):
    from kryptomime import GPGMIME
    return GPGMIME(keys['gpg1'],default_key=(sender,passphrase))

@fixture(scope='module')
def gpgreceiver(keys):
    from kryptomime import GPGMIME
    return GPGMIME(keys['gpg2'],default_key=receiver)

@fixture(scope='module')
def gpgthird(keys):
    from kryptomime import GPGMIME
    return GPGMIME(keys['gpg3'],default_key=third)

@fixture(scope='module')
def bilateral(request,keys):
    import gnupg
    from kryptomime import GPGMIME
    from ekklesia.data import tmpfname
    keyrings = [tmpfname() for i in range(2)]
    gpg1 = gnupg.GPG(keyring=keyrings[0],secring=keys['secrings'][0])
    gpg2 = gnupg.GPG(keyring=keyrings[1],secring=keys['secrings'][1])
    gpg1.import_keys(keys['pubkey1'])
    gpg1.import_keys(keys['pubkey2']) # sender knows receiver pubkey
    gpg2.import_keys(keys['pubkey1'])
    gpg2.import_keys(keys['pubkey2'])
    id1 = GPGMIME(gpg1,default_key=(sender,passphrase))
    id2 = GPGMIME(gpg2,default_key=receiver)
    def fin():
        import os
        for tmp in keyrings: os.unlink(tmp)
    request.addfinalizer(fin)
    return {'id1':id1,'id2':id2,'gpg1':gpg1,'gpg2':gpg2}

@fixture(scope='module')
def trilateral(request,keys):
    import gnupg
    from kryptomime import GPGMIME
    from ekklesia.data import tmpfname
    keyrings = [tmpfname() for i in range(3)]
    gpg1 = gnupg.GPG(keyring=keyrings[0],secring=keys['secrings'][0])
    gpg2 = gnupg.GPG(keyring=keyrings[1],secring=keys['secrings'][1])
    gpg3 = gnupg.GPG(keyring=keyrings[2],secring=keys['secrings'][2])
    for gpg in (gpg1,gpg2,gpg3):
        for i in range(1,3): gpg.import_keys(keys['pubkey%i'%i])
    id1 = GPGMIME(gpg1,default_key=(sender,passphrase))
    id2 = GPGMIME(gpg2,default_key=receiver)
    id3 = GPGMIME(gpg3,default_key=third)
    def fin():
        import os
        for tmp in keyrings: os.unlink(tmp)
    request.addfinalizer(fin)
    return {'id1':id1,'id2':id2,'id3':id3,'gpg1':gpg1,'gpg2':gpg2,'gpg2':gpg3}
