# -*- coding: utf-8 -*-
#
# Mails
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

from django.conf import settings
import logging
log = logging.getLogger(__name__)

def get_default_config(proto='imap'):
    # opts = config of id, proto=imap or smtp
    from ekklesia.mail import smtp_defaults, imap_defaults
    from django.conf import settings
    config = (smtp_defaults if proto=='smtp' else imap_defaults).copy()
    defcfg = {'imap':'EMAIL_DEFAULT_IMAP','smtp':'EMAIL_DEFAULT_SMTP'}[proto]
    defaults = getattr(settings, defcfg, None)
    if defaults: config.update(defaults)
    if proto=='smtp' and not config['user']:
        config['user'] = settings.EMAIL_HOST_USER
        config['password'] = settings.EMAIL_HOST_PASSWORD
    return config

def get_full_config(id,opts,proto='imap'):
    # opts = config of id, proto=imap or smtp
    config = get_default_config(proto)
    if proto in opts: config.update(opts[proto])
    if 'login' in opts: config['user'], config['password'] = opts['login']
    if not config['user']: config['user'] = opts.get('email',id) # set default
    return config

def get_all_configs(proto='smtp',join=False):
    from six import iteritems
    from ekklesia.data import hashable_dict
    ids = settings.EMAIL_IDS
    configs = {} # join=False -> id:config, join=True -> config:(ids,)
    for id, opts in iteritems(ids):
        idconfig = get_full_config(id,opts,proto)
        if not join:
            configs[id] = idconfig
            continue
        idconfig = hashable_dict(idconfig)
        if idconfig in configs:
            configs[idconfig].append(id)
        else:
            configs[idconfig] = [id]
    return configs

def gnupg_init(home=None):
    import gnupg, os
    if not home:
        home = settings.EMAIL_GPG_HOME or os.getcwd()
        log.debug('GPG home %s' % home)
    gpg = gnupg.GPG(homedir=home,verbose=False)
    return gpg

def gnupg_import_init(home=None,verbose=False):
    import gnupg, os
    if not home: home = settings.EMAIL_GPG_IMPORT_HOME
    if not home: home = os.path.join(os.getenv('HOME'),'.gnupg')
    if type(home) in (tuple,list):
        gpg = gnupg.GPG(keyring=home[0],secring=home[1],verbose=verbose)
    else:
        gpg = gnupg.GPG(homedir=home,verbose=verbose)
    if verbose: gnupg._logger.create_logger(10)
    return gpg

def get_full_key(crypto,opts,id):
    (keyid, pp) = opts['key']
    if not keyid: keyid = opts.get('email',id)
    keyid = crypto.find_key(keyid,secret=True)
    if not keyid: return None
    return (keyid,pp)

#-------------------------------------------------------------------------------------------------

def update_keyrings(debug_gpg=None,debug_import=None):
    "update or initialise keyring, if fresh regenerate from scratch"
    import shutil, os, gnupg, time
    from six import iteritems
    from email.utils import parseaddr

    if debug_import: gpgimport = debug_import
    else: gpgimport = gnupg_import_init()
    gpg = debug_gpg if debug_gpg else gnupg_init()
    pubkeys = gpg.list_keys(secret=False)
    seckeys = gpg.list_keys(secret=True)
    iseckeys = gpgimport.list_keys(secret=True)

    def find_key(name,keys):
        for key in keys:
            keyid = key['keyid']
            fingerprint = key['fingerprint']
            if keyid==name or fingerprint==name:
                return fingerprint,key
            for uid in key['uids']:
                email = parseaddr(uid)[1]
                if name==email:
                    return fingerprint,key
        return None, {}

    # sync id fullkeys
    ids = settings.EMAIL_IDS
    secids = []
    for identity, opts in iteritems(ids):
        if not 'key' in opts: continue
        email = opts.get('email',id)
        (keyid, pp) = opts['key']
        if not keyid: keyid = email
        fingerprint,info = find_key(keyid,seckeys)
        if not fingerprint:
            fingerprint,info = find_key(keyid,iseckeys)
            assert fingerprint, "seckey %s missing"%keyid
            expires = info['expires']
            if expires:
                expires = int(expires)
                assert expires > time.time(), "key %s has expired on %s"%\
                    (keyid,time.asctime(time.localtime(expires)))
            log.debug('importing sec %s', fingerprint)
            seckey = gpgimport.export_keys(fingerprint,secret=True)
            assert seckey, "seckey %s missing"%keyid
            gpg.import_keys(seckey)
            pubkey = gpgimport.export_keys(fingerprint,secret=False)
            assert pubkey, "pubkey %s missing"%keyid
            gpg.import_keys(pubkey)
        else:
            assert fingerprint not in secids, "key %s already used" % keyid
        secids.append(fingerprint)
    for fingerprint in seckeys.fingerprints:
        if fingerprint in secids: continue
        log.debug('deleting sec %s', fingerprint)
        gpg.delete_keys(fingerprint,subkeys=True)

    # sync pubkeys
    from idapi.models import PublicKey
    from django.utils import timezone

    pubids = []
    for key in PublicKey.objects.select_for_update().filter(active=True,keytype=PublicKey.PGP):
        data = key.data
        if not data: continue
        fingerprint = key.fingerprint
        keyid,info = find_key(fingerprint,pubkeys)
        if key.expires and key.expires < timezone.now():
            log.debug('key %s expired on %s', fingerprint,key.expires)
            key.active = False
            key.trust = PublicKey.DELETED
            key.save() # key will be deleted in next step
            continue
        if not keyid:
            log.debug('importing pub %s', fingerprint)
            gpg.import_keys(data['keydata'])
        pubids.append(fingerprint)
    for fingerprint in pubkeys.fingerprints:
        if fingerprint in pubids or fingerprint in secids: continue
        log.debug('deleting pub %s', fingerprint)
        gpg.delete_keys(fingerprint)

#-------------------------------------------------------------------------------------------------

def encrypt_mail(mail, user, sign, encrypt, crypto, skey):
    from idapi.models import PublicKey
    if sign and not skey:
        log.error('id key missing')
        return None
    if encrypt:
        recvkey = user.publickeys.filter(active=True,keytype=PublicKey.PGP).first()
        if not recvkey:
            log.error('user %s key missing', user.name)
            return None
        encrypt = recvkey.fingerprint
    defkey = {'default_key':skey[0],'passphrase':skey[1]}
    if encrypt and sign:
        mail,result = crypto.encrypt(mail,recipients=[encrypt],sign=skey[0],**defkey)
    elif encrypt:
        mail,result = crypto.encrypt(mail,recipients=[encrypt],sign=False)
    elif sign:
        mail,result = crypto.sign(mail,**defkey)
    assert result, "crypto failed"
    return mail

def decrypt_mail(msg, user, mfrom, crypto, gpg, skey):
    from idapi.models import PublicKey
    encrypted, signed = crypto.analyze(msg)
    need_crypto = encrypted or signed
    data = {'encrypted':encrypted,'signed':signed}
    if need_crypto and gpg:
        try:
            ukey = user.publickeys.get(active=True)
            trust = ukey.trust
            if not trust in (PublicKey.UNCONFIRMED,PublicKey.CONFIRMED,PublicKey.TRUSTED):
                ukey = None
            else:
                ukey = crypto.find_key(mfrom)
        except PublicKey.DoesNotExist: ukey = None
        if not ukey:
            log.error('no valid key for %s', mfrom)
            return None, None
        # FIXME decode unconfirmed keys
        if encrypted and skey:
            msg, verified, result = crypto.decrypt(msg,strict=False)
        else:
            verified, result = crypto.verify(msg,strict=False)
            if result['encrypted']:
                log.error('cannot decrypt message')
                return None, None
            msg, signed = crypto.strip_signature(msg)
        data['signed'] = result['signed']
        if verified:
            if not ukey in result['fingerprints']:
                data['verified'] = 'unknown'
            else:
                data['verified'] = dict(PublicKey.TRUST_CHOICES)[trust]
        need_crypto = False
    if need_crypto:
        assert not gpg, "decryption failed"
        # FIXME
        return msg, None
    return msg, data

def process_crypto(debug_gpg=None):
    """
    process all blos, incoming encrypted mails
    if INDEP crypto also outgoing crypto mail
    encrypted mail is stored as raw body incl. attachments
    """
    return

#-------------------------------------------------------------------------------------------------

def process_register(debug_gpg=None):
    return

#-------------------------------------------------------------------------------------------------

def encode_mail(sender, receiver, data):
    "data must be validated by check_mail"
    from kryptomime.mail import create_mail, create_mime, check_charset, protect_mail
    from time import time as epochtime
    import email.utils
    from email.mime.text import MIMEText
    from six import iteritems
    from idapi.models import Message
    subject = data['subject']
    time = data.get('date')
    if not time: time = epochtime()
    parts = data.get('parts',None)
    if parts: # multi-part
        mail = None
        for i,part in enumerate(parts):
            ctype = part.get('content-type','text/plain').lower().split('/')
            encoding = part.get('content-encoding')
            content = part['content']
            content, charset = check_charset(content,part.get('content-charset'))
            if not i:
                msg = create_mail(sender,receiver,subject,content,time=time,subtype=ctype[1],
                    charset=charset,encoding=encoding,attach=[])
            else:
                msg = create_mime(content,*ctype,charset=charset,encoding=encoding)
                filename= part.get('filename')
                filename = dict(filename=filename) if filename else {}
                msg.add_header('Content-Disposition', 'attachment', **filename)
            params = part.get('content-params',{})
            if params:
                for k,v in iteritems(params):
                    msg.set_param(k,v)
            if i: mail.attach(msg)
            else: mail = msg
    else: # single part
        ctype = data.get('content-type','text/plain').lower().split('/')
        encoding = data.get('content-encoding')
        body, charset = check_charset(data['content'],data.get('content-charset'))
        mail = create_mail(sender,receiver,subject,body,time=time,subtype=ctype[1],
                charset=charset,encoding=encoding)
        params = data.get('content-params',{})
        if params:
            for k,v in iteritems(params):
                mail.set_param(k,v)
    return protect_mail(mail)

def check_mail(input,user,app):
    from time import time as epochtime
    from ekklesia.mail import Template
    from idapi.models import Message
    from rest_framework.exceptions import ValidationError, PermissionDenied, MethodNotAllowed
    ids = settings.EMAIL_IDS
    templates = settings.EMAIL_TEMPLATES
    if app:
        clients = settings.EMAIL_CLIENTS
        try: permissions = clients[app.client_id]
        except KeyError:
            raise PermissionDenied(dict(error='client_not_permitted',
                details='client does not have permission to use the email interface'))
    if not 'identity' in input:
        raise ValidationError(dict(error='identity_missing',
            details='the identity is not specified'))
    identity = input['identity']
    if not identity in ids:
        raise ValidationError(dict(error='identity_unknown',
            details='the identity is unknown'))
    opts = ids[identity]
    if app:
        if not identity in permissions:
            raise ValidationError(dict(error='identity_not_permitted',
                details='the identity is not permitted for this client'))
        recv, send, attach = permissions[identity]
        if send == False: raise MethodNotAllowed('post')
    else:
        recv = send = attach = True
    template = input.get('template',None)
    if template:
        if send is None and 'templates' in opts:
            if not template in opts['templates']:
                raise ValidationError(dict(error='template_not_permitted',
                    details='the template is not permitted for this identity'))
        if not template in templates:
            raise ValidationError(dict(error='template_unknown',
                details='template is unknown'))
        subject,body = templates[template]
        if type(subject)==str: subject = Template(subject)
        if type(body)==str: body = Template(body)
    else:
        subject, body = Template(u'{subject}'), Template(u'{body}')
    sign, encrypt  = input.get('sign',False),input.get('encrypt',False)
    if sign and not 'key' in opts:
        raise ValidationError(dict(error='signing',
            details='signing not supported for this identity'))
    if encrypt and not user.publickeys.filter(active=True).exists():
        raise ValidationError(dict(error='pubkey_missing',
            details='the public key for this user is missing'))

    def check_content(data,out,extra=(),force_text=False):
        content = data.get('content')
        if not content:
            raise ValidationError(dict(error='content_missing',
                details='message content is missing'))
        for field in ('content-type','content-params','content-charset','content-encoding')+extra:
            if not field in data: continue
            if field=='content-params' and type(data[field])!=dict:
                raise ValidationError(dict(error='type_error',
                    details='content params must be a dict'))
            elif field=='content-type':
                ctype = data[field].split('/')
                if not len(ctype)==2 or not (ctype[0] and ctype[1]):
                    raise ValidationError(dict(error='type_error',
                        details="invalid content type"))
                if force_text and not ctype[0]:
                    raise ValidationError(dict(error='type_error',
                        details="content-type text expected"))
            out[field] = data[field]
        return content

    main = {}
    content = check_content(input,main,force_text=True)
    data = dict(subject=subject(**content),encrypt=encrypt,sign=sign,date=epochtime())
    main['content'] = body(**content)

    def check_encoding(data):
        from kryptomime.mail import check_charset
        charset = data.get('content-charset')
        encoding = data.get('content-encoding')
        if not charset and not encoding: return
        if encoding=='7bit':
            if not charset: charset = 'us-ascii'
            elif not charset in ('ascii','us-ascii'):
                raise ValidationError(dict(error='type_error',
                    details="encoding and charset mismatch"))
        try: check_charset(data['content'], charset)
        except UnicodeError:
            raise ValidationError(dict(error='type_error',
                details="charset does not match data"))

    check_encoding(main)
    if 'parts' in input:
        if not attach:
            raise ValidationError(dict(error='attachment_not_permitted',
                details='attachments are not permitted for this client'))
        parts = [main]
        attachments = input.get('parts',[])
        if not isinstance(attachments,(list,tuple)):
            raise ValidationError(dict(error='type_error',
                details='parts must be a list'))
        for a in attachments:
            part = {}
            if type(a)==str: part['content'] = a
            elif type(a)==dict: # dict
                part['content'] = check_content(a,part,extra=('filename',))
                check_encoding(part)
            else:
                raise ValidationError(dict(error='type_error',
                    details='part must be a string or dict'))
            parts.append(part)
        data['parts'] = parts
    else:
        data.update(main)
    # whether to keep sent msg (explicit delete) or auto-delete after send
    data['keep'] = input.get('keep',False)
    return data, identity, sign or encrypt

def send_mail_direct(data, user, identity, debug=None,debug_gpg=None):
    import email.utils
    opts = settings.EMAIL_IDS[identity]
    sender, sname = opts['email'], opts.get('name','')
    if sname: sender = email.utils.formataddr((sname,sender))
    mail = encode_mail(sender, user.email, data)
    encrypt, sign = data['encrypt'], data['sign']
    crypto = encrypt or sign
    if crypto:
        from kryptomime.pgp import GPGMIME
        if debug_gpg: gpg = debug_gpg
        else: gpg = gnupg_init()
        crypto = GPGMIME(gpg)
        if 'key' in opts: skey = get_full_key(crypto,opts,identity)
        mail = encrypt_mail(mail, user, sign, encrypt, crypto, skey)
    if debug: smtp = debug
    else:
        from ekklesia.mail import smtp_init
        config = get_full_config(identity,opts,'smtp')
        smtp = smtp_init(config)
        assert smtp.open(), 'smtp open failed'
    try: status = smtp.send(mail)
    except: status = False
    smtp.close()
    return status

def send_queue(msgid, debug=None, debug_gpg=None):
    from django.utils import timezone
    from django.db import transaction
    from idapi.models import Message
    from datetime import timedelta
    with transaction.atomic():
        try: msg = Message.objects.select_for_update().get(pk=msgid)
        except Message.DoesNotExist:
            log.error('message %s not found',msgid)
            return False
        if not (msg.outgoing and msg.email):
            log.error('invalid message %s',msgid)
            return False
        if msg.status != Message.QUEUED:
            log.error('message %s is not queued',msgid)
            return True
        expired = timezone.now()-timedelta(seconds=settings.EMAIL_LOCK_TIMEOUT)
        if msg.locked and msg.locked>=expired:
            log.error('message %s is already locked',msgid)
            return False
        msg.locked = timezone.now()
        msg.save(update_fields=('locked',))
    msg.locked = None
    status = send_mail_direct(msg.data, msg.user, msg.identity, debug, debug_gpg)
    if status:
        msg.status = Message.SENT
        if not msg.data.get('keep',False):
            msg.delete()
            return True
    else: msg.status = Message.FAILED
    msg.time = timezone.now()
    msg.save(update_fields=('locked','status','time'))
    return True

def send_mail(data, user, app, debug=None,debug_gpg=None):
    from idapi.models import Message
    from idapi.tasks import send_background
    data, identity, crypto = check_mail(data,user,app)
    queue = settings.EMAIL_QUEUE
    if not queue or (not crypto and queue=='crypto'):
        # send directly
        status = send_mail_direct(data, user, identity, debug, debug_gpg)
        return dict(status='sent' if status else 'failed')
    else: # queue
        msg = Message.objects.create(user=user,application=app,identity=identity,
            email=True,outgoing=True,crypto=crypto, data=data)
        if settings.BROKER_URL:
            if debug or debug_gpg:
                send_queue(msg.pk, debug, debug_gpg) # direct
            elif settings.USE_CELERY:
                send_background.delay(msg.pk) # start task
        return dict(status='queued',msgid=msg.pk)

def send_id_mails(smtp,identity,opts,crypto,isopen):
    from django.utils import timezone
    from datetime import timedelta
    from idapi.models import Message
    from django.db.models import Q
    from django.db import transaction
    import email.utils
    sender, sname = opts['email'], opts.get('name','')
    if sname: sender = email.utils.formataddr((sname,sender))
    if not 'key' in opts or not crypto: skey = None
    else: skey = get_full_key(crypto,opts,identity)
    query = Message.objects.filter(identity=identity,outgoing=True,email=True,status=Message.QUEUED)
    expired = timezone.now()-timedelta(seconds=settings.EMAIL_LOCK_TIMEOUT)
    query = query.filter(Q(locked=None) | Q(locked__lt=expired))
    if not crypto: query = query.filter(crypto=False)
    while True:
        with transaction.atomic():
            msg = query.select_for_update().first() # lock one-by-one
            if msg is None: break
            msg.locked = timezone.now()
            msg.save(update_fields=('locked',))
        msg.locked = None
        msg.time = timezone.now()
        msg.status = Message.FAILED
        if not isopen:
            assert smtp.open(), 'smtp open failed'
            log.debug('smtp opened')
            isopen=True
        mail = encode_mail(sender, msg.user.email, msg.data)
        encrypt, sign = msg.data.get('encrypt',False), msg.data.get('sign',False)
        needcrypto = sign or encrypt
        assert msg.crypto == needcrypto, "crypto mismatch"
        assert crypto or not needcrypto, "unprocessed crypto mail"
        if needcrypto:
            mail = encrypt_mail(mail, msg.user, sign, encrypt, crypto, skey)
        if mail:
            try: status = smtp.send(mail)
            except: status = False
            if status:
                if not msg.data.get('keep',True):
                    msg.delete()
                    continue
                msg.status = Message.SENT
        msg.save(update_fields=('locked','status','time'))
    return isopen

def send_mails(joint=True,connections=None,debug=None,debug_gpg=None):
    from kryptomime.pgp import GPGMIME
    from ekklesia.mail import smtp_init
    from six import iteritems
    configs = get_all_configs('smtp',joint)
    indep_crypto = getattr(settings, 'EMAIL_INDEP_CRYPT', False)
    ids = settings.EMAIL_IDS
    if indep_crypto: crypto = None
    else:
        if debug_gpg: gpg = debug_gpg
        else: gpg = gnupg_init()
        crypto = GPGMIME(gpg)
    for k, v in iteritems(configs):
        if joint: config, confids = k, v
        else: config, confids = dict(v), [k]
        if debug: smtp = debug
        elif connections is None:
            smtp = smtp_init(config)
        else:
            smtp = connections.get(config)
            if not smtp:
                smtp = smtp = smtp_init(config)
                connections[config] = smtp
        isopen = False
        for identity in confids:
            isopen = send_id_mails(smtp,identity,ids[identity],crypto,isopen)
        if isopen and connections is None:
            smtp.close()
            log.debug('smtp closed')

#-------------------------------------------------------------------------------------------------

def decode_mail(msg, idemail, crypto, gpg, skey):
    import email.utils
    from accounts.models import Account
    from idapi.models import Message, PublicKey
    import time, calendar
    mfrom = msg.get('from', [])
    mfrom = email.utils.parseaddr(mfrom)[1]
    tos = msg.get_all('to', [])
    ccs = msg.get_all('cc', [])
    mto = [to[1] for to in email.utils.getaddresses(tos + ccs)]
    msubject = msg.get('subject', '')
    mdate = email.utils.parsedate_tz(msg.get('date'))
    if mdate: mdate = email.utils.mktime_tz(mdate)
    else: mdate = calendar.timegm(msg.time.timetuple())
    if not idemail in mto:
        log.error('receiver %s not in recipients', idemail)
        return None
    try: user = Account.objects.get(email=mfrom)
    except Account.DoesNotExist:
        log.error('unknown sender %s', mfrom)
        return None
    data = dict(subject=msubject,date=mdate)

    msg, cdata = decrypt_mail(msg, user, mfrom, crypto, gpg, skey)
    if not msg: return None
    if not cdata:
        assert not gpg, "decryption failed"
        # FIXME
        data['raw'] = msg.as_string()
    elif msg:
        data.update(cdata)
        if msg.is_multipart():
            parts = []
            for sub in msg.get_payload():
                s, t = sub.get_payload(), sub.get_content_type()
                if not type(s)==str: s = s.as_string()
                p = {'content-type':t,'content':s}
                f = sub.get_filename(None)
                if not f is None: p['filename'] = f
                par = sub.get_params((None,None))[1:]
                par = dict((k,v) for k,v in par if k!='charset')
                if par: p['content-params'] = par
                c = sub.get_content_charset(None)
                if c: p['content-charset'] = c
                enc = sub.get('content-transfer-encoding',None)
                if enc: p['content-encoding'] = enc
                parts.append(p)
            data['parts'] = parts
        else:
            data['body'] = msg.get_payload()
            data['content-type'] = msg.get_content_type()
            par = msg.get_params((None,None))[1:]
            par = dict((k,v) for k,v in par if k!='charset')
            if par: data['content-params'] = par
            c = msg.get_content_charset(None)
            if c: data['content-charset'] = c
            enc = msg.get('content-transfer-encoding',None)
            if enc: data['content-encoding'] = enc
    newmsg = Message(user=user,email=True,outgoing=False,crypto=not cdata,data=data)
    return newmsg

def save_mail(mail, identity, idemail, crypto, gpg, skey, notify=None):
    msg = decode_mail(mail, idemail, crypto, gpg, skey)
    if not msg: return False
    msg.identity = identity
    msg.save()
    if settings.BROKER_URL: # notify
        if msg.crypto: # not decrypted
            if settings.USE_CELERY:
                decrypt_background.delay(msg.pk) # start task
            # otherwise decrypt in mailio task
        else: # ready for clients
            from account.models import send_broker_msg
            msg = dict(format='mail',version=(1,0),msgid=msg.pk)
            send_broker_msg(msg, settings.MAILIN_EXCHANGE, settings.MAILIN_QUEUE,connection=notify)
    return True

def store_mail(mail,identity=None,decrypt=False,notify=None):
    from six import iteritems
    from kryptomime.mail import protect_mail

    mail = protect_mail(mail,sevenbit=False)
    ids = settings.EMAIL_IDS

    def find_identity(recv):
        for id,opts in iteritems(ids):
            idemail = opts.get('email',id)
            if idemail in recv: return id, opts, idemail
        return None, None, None

    if identity:
        opts = ids[identity]
        idemail = opts.get('email',identity)
    else:
        import email.utils
        recv = mail.get_all('to', []) + mail.get_all('cc', [])
        recv = [to[1] for to in email.utils.getaddresses(recv)]
        identity, opts, idemail = find_identity(recv)
        if not identity:
            log.error('unknown receiver')
            return False

    indep_crypto = getattr(settings, 'EMAIL_INDEP_CRYPT', False)
    if indep_crypto and not decrypt:
        gpg, crypto, skey = None, None, None
    else:
        from kryptomime.pgp import GPGMIME
        gpg = gnupg_init()
        if not 'key' in opts: skey = None
        else: skey = get_full_key(GPGMIME(gpg),opts,identity)
        crypto = GPGMIME(gpg,default_key=skey)
    return save_mail(mail, identity, idemail, crypto, gpg, skey, notify)

def get_id_mails(server,identity,opts,gpg,isopen,notify=None,debug=None,keep=False):
    from kryptomime.pgp import GPGMIME
    idemail = opts['email']
    if not gpg: crypto, skey = None, None
    else:
        if not 'key' in opts: skey = None
        else: skey = get_full_key(GPGMIME(gpg),opts,identity)
        crypto = GPGMIME(gpg,default_key=skey)
    if debug:
        imap = server.get_imap(idemail,keep=keep,readonly=keep)
        if imap is None:
            log.error('mailbox for %s not found', idemail)
            return isopen
    else: imap = server
    if not isopen:
        assert imap.open(), 'imap open failed'
        log.debug('imap opened')
        isopen=True
    folder = opts.get('imapfolder')
    if folder:
        try: imap.set_folder(folder)
        except:
            log.error('folder %s for %s not found', folder,idemail)
            return isopen
    log.debug('%i mails for %s to %s', len(imap),idemail)
    for mail, flags in imap:
        save_mail(mail, identity, idemail, crypto, gpg, skey, notify)
    return isopen

def get_mails(joint=True,connections=None,notify=None,debug=None,debug_gpg=None,keep=False):
    from ekklesia.mail import IMAPSource, imap_init
    from six import iteritems
    configs = get_all_configs('imap',True)
    ids = settings.EMAIL_IDS
    indep_crypto = getattr(settings, 'EMAIL_INDEP_CRYPT', False)
    if indep_crypto: gpg = None
    elif debug_gpg: gpg = debug_gpg
    else: gpg = gnupg_init()
    for k, v in iteritems(configs):
        if joint: config, confids = k, v
        else: config, confids = dict(v), [k]
        if debug: server = debug
        elif connections is None:
            server = imap_init(config,keep=keep)
        else:
            server = connections.get(config)
            if not server:
                server = imap_init(dict(config),keep=keep)
                connections[config] = server
        isopen = False
        for identity in confids:
            isopen = get_id_mails(server,identity,ids[identity],gpg,isopen,notify,debug,keep)
        if isopen and not debug and connections is None:
            server.close()
            log.debug('imap closed')
