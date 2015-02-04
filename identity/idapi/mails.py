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

def get_default_config(proto='imap'):
    # opts = config of id, proto=imap or smtp
    from django.conf import settings
    config = {}
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
    from ekklesia.mail import SMTPConfig, IMAPConfig
    from six import iteritems
    Config = IMAPConfig if proto=='imap' else SMTPConfig
    ids = getattr(settings, 'EMAIL_IDS', None)
    configs = {} # join=False -> id:config, join=True -> config:(ids,)
    for id, opts in iteritems(ids):
        config = get_full_config(id,opts,proto)
        idconfig = Config(**config)
        if not join:
            configs[id] = idconfig
        elif idconfig in configs:
            configs[idconfig].append(id)
        else:
            configs[idconfig] = [id]
    return configs

def gnupg_init(home=None):
    import gnupg, os
    if not home:
        home = getattr(settings, 'EMAIL_GPG_HOME') or os.getcwd()
    gpg = gnupg.GPG(homedir=home,verbose=False)
    return gpg

def gnupg_import_init(home=None,verbose=False):
    import gnupg, os
    if not home: home = getattr(settings, 'EMAIL_GPG_IMPORT_HOME')
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
    else: gpgimport = gnupg_import_init
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
    ids = getattr(settings, 'EMAIL_IDS', None)
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
            #print 'importing sec', fingerprint
            seckey = gpgimport.export_keys(fingerprint,secret=True)
            assert seckey, "seckey %s missing"%keyid
            gpg.import_keys(seckey)
            pubkey = gpgimport.export_keys(fingerprint,secret=False)
            assert pubkey, "pubkey %s missing"%keyid
            gpg.import_keys(pubkey)
        else:
            assert fingerprint not in secids, "key %s already used" % keyid
        #print info
        secids.append(fingerprint)
    for fingerprint in seckeys.fingerprints:
        if fingerprint in secids: continue
        #print 'deleting seckey',fingerprint
        gpg.delete_keys(fingerprint,subkeys=True)

    # sync pubkeys
    from idapi.models import PublicKey
    from django.utils import timezone

    pubids = []
    for key in PublicKey.objects.filter(active=True,keytype=PublicKey.PGP):
        data = key.data
        #print data, key.user
        if not data: continue
        fingerprint = data['fingerprint']
        keyid,info = find_key(fingerprint,pubkeys)
        #print keyid,info,fingerprint
        #print key.expires, timezone.now()
        if key.expires and key.expires < timezone.now():
            #print 'key %s expired on %'%(fingerprint,key.expires)
            key.active = False
            key.trust = PublicKey.DELETED
            key.save() # key will be deleted in next step
            continue
        if not keyid:
            #print 'importing',fingerprint
            gpg.import_keys(data['keydata'])
        pubids.append(fingerprint)
    for fingerprint in pubkeys.fingerprints:
        if fingerprint in pubids or fingerprint in secids: continue
        #print 'deleting pubkey',fingerprint
        gpg.delete_keys(fingerprint)

#-------------------------------------------------------------------------------------------------

def encrypt_mail(msg, mail, crypto, skey):
    encrypt, sign = msg.data.get('encrypt',False), msg.data.get('sign',False)
    needcrypto = sign or encrypt
    assert msg.crypto == needcrypto, "crypto mismatch"
    assert crypto or not needcrypto, "unprocessed crypto mail"
    if not msg.crypto: return mail
    if sign and not skey:
        #print 'id key missing'
        return None
    if encrypt:
        recvkey = msg.user.publickeys.filter(active=True)
        if not recvkey.exists():
            #print 'user key missing'
            return None
    defkey = {'default_key':skey[0],'passphrase':skey[1]}
    if encrypt:
        mail,result = crypto.encrypt(mail,sign=skey[0] if sign else False,**defkey)
    elif sign:
        mail,result = crypto.sign(mail,**defkey)
    #else: crypto mismatch'
    assert result, "crypto failed"
    return mail

def decrypt_mail(msg, user, mfrom, crypto, gpg, skey):
    from idapi.models import PublicKey
    encrypted, signed = crypto.analyze(msg)
    #print encrypted, signed
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
            #print 'no valid key for',mfrom
            return None, None
        # FIXME decode unconfirmed keys
        if encrypted and skey:
            msg, verified, result = crypto.decrypt(msg,strict=False)
        else:
            verified, result = crypto.verify(msg,strict=False)
            if result['encrypted']:
                #print 'cannot decrypt'
                return None, None
            msg, signed = crypto.strip_signature(msg)
        #print verified, result
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

def encode_mail(msg, sender):
    from kryptomime.mail import create_mail, create_mime, check_charset
    from time import time as epochtime
    import email.utils
    from email.mime.text import MIMEText
    from six import iteritems
    from idapi.models import Message
    user, data = msg.user, msg.data
    receiver = user.email
    subject = data['subject']
    time = data.get('date',epochtime())
    parts = data.get('parts',None)
    if parts: # multi-part
        mail = None
        for i,part in enumerate(parts):
            ctype = part.get('content-type','text/plain').lower().split('/')
            encoding = part.get('content-encoding')
            content = part['content']
            content, charset = check_charset(content,part.get('content-charset'))
            if i:
                msg = create_mime(content,*ctype,charset=charset,encoding=encoding)
                filename= part.get('filename')
                filename = dict(filename=filename) if filename else {}
                msg.add_header('Content-Disposition', 'attachment', **filename)
            else:
                assert ctype[0]=='text'
                msg = create_mail(sender,receiver,subject,content,time=time,subtype=ctype[1],
                    charset=charset,encoding=encoding)
            params = part.get('content-params',{})
            if params:
                assert type(params) == dict
                for k,v in iteritems(params):
                    msg.set_param(k,v)
            if i: mail.attach(msg)
            else: mail = msg
    else: # single part
        ctype = data.get('content-type','text/plain').lower().split('/')
        assert ctype[0]=='text'
        encoding = data.get('content-encoding')
        body, charset = check_charset(data['content'],data.get('content-charset'))
        mail = create_mail(sender,receiver,subject,body,time=time,subtype=ctype[1],
                charset=charset,encoding=encoding)
        params = data.get('content-params',{})
        if params:
            assert type(params) == dict
            for k,v in iteritems(params):
                mail.set_param(k,v)
    #print mail
    return mail

def create_mail(input,app,user):
    from time import time as epochtime
    from ekklesia.mail import Template
    from idapi.models import Message
    ids = getattr(settings, 'EMAIL_IDS', {})
    templates = getattr(settings, 'EMAIL_TEMPLATES', {})
    clients = getattr(settings, 'EMAIL_CLIENTS', {})
    try:
        allowed = clients[app.client_id]
        identity = input['identity']
        opts = ids[identity]
        recv, send, attach = allowed[identity]
        assert send!=False
    except: return None
    template = input.get('template',None)
    if send is None and 'templates' in opts:
        if not template in opts['templates']: return None
    if template:
        subject,body = templates[template]
        if type(subject)==str: subject = Template(subject)
        if type(body)==str: body = Template(body)
    else:
        subject, body = Template(u'{subject}'), Template(u'{body}')
    sign, encrypt  = input.get('sign',False),input.get('encrypt',False)
    if sign and not 'key' in opts:
        return None
    if encrypt and not user.publickeys.filter(active=True).exists():
        return None
    content = input.get('content',{})
    if not content: return None
    data = {'subject':subject(**content),'encrypt':encrypt,'sign':sign,'date':epochtime()}
    main = {'content':body(**content)}
    for field in ('content-type','content-params','content-charset','content-encoding'):
        if not field in input: continue
        if field=='content-params' and type(input[field])!=dict: return None
        main[field] = input[field]
    if 'parts' in input:
        parts = [main]
        attachments = input.get('parts',[])
        if not type(attachments)==dict: return None
        for a in attachments:
            part = {}
            if type(a)==str: part['content'] = a
            elif type(a)==dict: # dict
                if not 'content' in a: return None
                part['content'] = a['content']
                for field in ('content-type','content-params','content-charset','content-encoding','filename'):
                    if not field in a: continue
                    if field=='content-params' and type(a[field])!=dict: return None
                    part[field] = a[field]
            else: return None
            attachments.append(p)
        data['parts'] = attachments
    else:
        data.update(main)
    data['status'] = 'queued'
    # whether to keep sent msg (explicit delete) or auto-delete after send
    data['keep'] = input.get('keep',True)
    #print data
    msg = Message(user=user,application=app,identity=identity,
        email=True,outgoing=True,crypto=(sign or encrypt), data=data)
    #print msg.__dict__, user.email
    msg.save()
    # FIXME: notify encrypt/send
    return msg

def save_mail(user,app,identity,template=None,tmplargs={},attachments=[],sign=True,encrypt=False):
    from django.utils import timezone
    from ekklesia.mail import Template
    from idapi.models import Message
    from django.contrib.auth import get_user_model
    User = get_user_model()
    from oauth2_provider.models import get_application_model
    Application = get_application_model()
    if type(user)==str: user = User.objects.get(username=user)
    if type(app)==str: app = Application.objects.get(client_id=app)
    ids = getattr(settings, 'EMAIL_IDS', {})
    templates = getattr(settings, 'EMAIL_TEMPLATES', {})
    clients = getattr(settings, 'EMAIL_CLIENTS', {})
    indep_crypto = getattr(settings, 'EMAIL_INDEP_CRYPT', False)
    allowed = clients[app.client_id]
    recv,send,attach = allowed[identity]
    assert send != False, "sending not allowed"
    opts = ids[identity]
    if send is None and 'templates' in opts:
        assert template in opts['templates'], 'template not allowed'
    if template:
        subject,body = templates[template]
        if type(subject)==str: subject = Template(subject)
        if type(body)==str: body = Template(body)
    else:
        subject, body = Template('{subject}'), Template('{body}')
    assert not sign or 'key' in opts, "cannot sign"
    if encrypt:
        assert user.publickeys.filter(active=True).exists(), 'user key missing'
    data = {'subject':subject(**tmplargs),'body':body(**tmplargs),'encrypt':encrypt,'sign':sign}
    msg = Message(user=user,application=app,identity=identity,email=True,
        outgoing=True,crypto=(sign or encrypt), data=data)
    #print msg.__dict__, user.email
    msg.save()
    return msg

def send_id_mails(smtp,identity,opts,crypto,isopen):
    from kryptomime.pgp import GPGMIME
    from ekklesia.mail import SMTPOutput
    from django.utils import timezone
    from idapi.models import Message
    import email.utils
    sender, sname = opts['email'], opts.get('name','')
    if sname: sender = email.utils.formataddr((sname,sender))
    if not 'key' in opts or not crypto: skey = None
    else: skey = get_full_key(crypto,opts,identity)
    msgs = Message.objects.filter(identity=identity,outgoing=True,email=True)
    if not crypto: msgs = msgs.filter(crypto=False)
    for msg in msgs.all():
        #print msg, msg.data
        if not isopen:
            assert smtp.open(), 'smtp open failed'
            #print 'smtp opened'
            isopen=True
        mail = encode_mail(msg, sender)
        mail = encrypt_mail(msg, mail, crypto, skey)
        if not mail: continue
        #print mail
        try: status = smtp.send(mail)
        except: status = False
        #print status
        if not status:
            msg.status = Message.SENT
            if not msg.data.get('keep',True):
                msg.delete()
                continue
        else: msg.status = Message.FAILED
        msg.time = timezone.now()
        msg.save()
    return isopen

def send_mails(joint=True,connections=None,debug=None,debug_gpg=None):
    from kryptomime.pgp import GPGMIME
    from ekklesia.mail import smtp_init
    from six import iteritems
    configs = get_all_configs('smtp',joint)
    indep_crypto = getattr(settings, 'EMAIL_INDEP_CRYPT', False)
    ids = getattr(settings, 'EMAIL_IDS', None)
    if indep_crypto: crypto = None
    else:
        if debug_gpg: gpg = debug_gpg
        else: gpg = gnupg_init()
        crypto = GPGMIME(gpg)
    for k, v in iteritems(configs):
        if joint: config, confids = k, v
        else: config, confids = v, [k]
        if debug: smtp = debug
        elif connections is None:
            smtp = smtp_init(config._asdict())
        else:
            smtp = connections.get(config)
            if not smtp:
                smtp = smtp = smtp_init(config._asdict())
                connections[config] = smtp
        isopen = False
        for identity in confids:
            isopen = send_id_mails(smtp,identity,ids[identity],crypto,isopen)
        if isopen and connections is None:
            smtp.close()
            #print 'smtp closed'

#-------------------------------------------------------------------------------------------------

def decode_mail(msg, idemail, crypto, gpg, skey):
    import email.utils
    from accounts.models import Account
    from idapi.models import Message, PublicKey
    #import time
    #msgtime = time.localtime(msg.get_date())
    mfrom = msg.get('from', [])
    mfrom = email.utils.parseaddr(mfrom)[1]
    tos = msg.get_all('to', [])
    ccs = msg.get_all('cc', [])
    mto = [to[1] for to in email.utils.getaddresses(tos + ccs)]
    msubject = msg.get('subject', '')
    mdate = email.utils.parsedate_tz(msg.get('date', ''))
    if mdate: mdate = email.utils.mktime_tz(mdate)
    #print msubject, mdate, flags
    if not idemail in mto:
        #print 'receiver %s not in recipients' % idemail
        return None
    try: user = Account.objects.get(email=mfrom)
    except Account.DoesNotExist:
        #print 'unknown sender', mfrom
        return None
    data = {'subject':msubject,'date':mdate}

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
    #print data
    newmsg = Message(user=user,email=True,outgoing=False,crypto=not cdata,data=data)
    #print newmsg.__dict__
    return newmsg

def get_id_mails(server,identity,opts,gpg,isopen,debug=None,keep=False):
    from kryptomime.pgp import GPGMIME
    idemail = opts['email']
    if not gpg: crypto, skey = None, None
    else:
        if not 'key' in opts: skey = None
        else: skey = get_full_key(GPGMIME(gpg),opts,identity)
        crypto = GPGMIME(gpg,default_key=skey)
    if debug:
        #try:
        imap = server.get_imap(idemail,keep=keep,readonly=keep)
        if imap is None:
        #except:
            #print 'mailbox for %s not found' % idemail
            return isopen
    else: imap = server
    if not isopen:
        assert imap.open(), 'imap open failed'
        #print 'imap opened'
        isopen=True
    folder = opts.get('imapfolder')
    if folder:
        try: imap.set_folder(folder)
        except:
            #print 'folder %s for %s not found' % (folder,idemail)
            return isopen
    #print len(imap),'mails for',idemail,id
    for msg, flags in imap:
        newmsg = decode_mail(msg, idemail, crypto, gpg, skey)
        newmsg.identity = identity
        if newmsg: newmsg.save()
    return isopen

def get_mails(joint=True,connections=None,debug=None,debug_gpg=None,keep=False):
    from ekklesia.mail import IMAPSource, imap_init
    from six import iteritems
    configs = get_all_configs('imap',True)
    ids = getattr(settings, 'EMAIL_IDS', None)
    indep_crypto = getattr(settings, 'EMAIL_INDEP_CRYPT', False)
    if indep_crypto: gpg = None
    elif debug_gpg: gpg = debug_gpg
    else: gpg = gnupg_init()
    for k, v in iteritems(configs):
        if joint: config, confids = k, v
        else: config, confids = v, [k]
        if debug: server = debug
        elif connections is None:
            server = imap_init(config._asdict(),keep=keep)
        else:
            server = connections.get(config)
            if not server:
                server = imap_init(config._asdict(),keep=keep)
                connections[config] = server
        isopen = False
        for identity in confids:
            isopen = get_id_mails(server,identity,ids[identity],gpg,isopen,debug,keep)
        if isopen and not debug and connections is None:
            server.close()
            #print 'imap closed'
