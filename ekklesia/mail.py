# -*- coding: utf-8 -*-
#
# Secure E-mail
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

from __future__ import print_function

class Template(object):
    """
    Template system with support for nesting.

    :param str format: Python .format string for '{variable}' substitutions (default '{x}')
    :param dict defaults: default values for variables
    :param sub: sub-templates for variables
    :type sub: dict of Templates or None (for lists with separator)
    :param str separator: the separator used for separating the output of the sub-templates (default '\n')

    Attributes:
        keys: the set of keys extracted from the format

    """

    def __init__(self, format = None, defaults= None, sub = None, separator='\n'):
        from string import Formatter
        from six import iteritems
        self.format = format or '{x}'
        self.defaults = defaults or {}
        self.sub = sub or {}
        self.separator = separator
        keys = set()
        for literal_text, field_name, format_spec, conversion in Formatter().parse(self.format):
            if field_name: keys.add(field_name)
        self.keys = keys
        for key in list(self.defaults.keys())+list(self.sub.keys()):
            if key in keys: continue
            print('warning: key %s missing in template',key)
        for key,tmpl in iteritems(self.sub):
            assert tmpl is None or isinstance(tmpl,Template), '%s must be a template' % key

    def _fill(self, level, **kwargs):
        from collections import Iterable
        from six import iteritems
        vals = self.defaults.copy()
        vals.update(kwargs)
        assert self.keys <= set(vals.keys()), 'keys missing in format'
        # replace subs first
        slevel = str(level+1)
        for key,tmpl in iteritems(self.sub):
            s, x = '', vals[key]
            assert isinstance(x,Iterable), "value must be iterable"
            n = len(x)
            if type(tmpl) == str:
                tmpl = Template(tmpl,separator=self.separator)
            for i,v in enumerate(x):
                if tmpl is None:
                    if i: s+= self.separator
                    s += str(v)
                    continue
                if i: s+= tmpl.separator
                if not isinstance(v,dict): # just a list
                    s += tmpl._fill(level+1,x=v,i=i+1,n=n,**{'i'+slevel:i+1,'n'+slevel:n,'x'+slevel:v})
                    continue
                subvals = vals.copy()
                del subvals[key]
                subvals.update({'i':str(i+1),'n':n,'i'+slevel:i+1,'n'+slevel:n})
                subvals.update(v)
                s += tmpl._fill(level+1,**subvals)
            vals[key] = s
        return self.format.format(**vals)

    def __call__(self, **kwargs):
        """
        :returns str: the formatted string

        The variables are filled as follows:
        1. missing values are replaced with the defaults
        2. each variable using a subtemplate is replaced with the concatenated strings
            of each value, separated by the subtemplates separator.
            If the subtemplate is set to None, the strings of the values are
            separated by the templates separator.
            If the value for a subtemplate is not a dict, 'x' and 'x<level>' are set to the current object.
            In subtemplates the values of 'i' and 'i<level>,'n' and 'n<level>' default to the current
            object index (starting at 1) and the number of objects, respectively. 
            level ist the nesting level starting at 1 for top.
            All values of the upper level are passed to the subtemplate,
            except for its value, which is expended.
        """
        return self._fill(0,**kwargs)

from collections import namedtuple

GPGConfig = namedtuple("GPGConfig", 'binary home keyring secring sender passphrase')
gpg_defaults = dict(binary='gpg',home=None, keyring=None, secring=None, sender=None, passphrase=None)
gpg_spec="""
[gnupg]
binary = string(default='gpg')
home = string(default='~/.gnupg')
keyring = string
secring = string
sender = string
passphrase = string
"""

def gpg_init(config, verbose=False):
    from kryptomime.pgp import GPGMIME
    import gnupg
    tmp = gpg_defaults.copy()
    tmp.update(config)
    config = GPGConfig(**tmp)
    gpg = gnupg.GPG(binary=config.binary,homedir=config.home,
        keyring=config.keyring,secring=config.secring,verbose=verbose)
    return gpg, GPGMIME(gpg=gpg,default_key=(config.sender,config.passphrase))

def gpg_key(config):
    sender = config.sender
    if not sender: sender=('','')
    return {'default_key':sender[0],'passphrase':sender[1]}

smtp_defaults = dict(host='localhost', port=587, user=None, password=None, tls=True, certfile=None, keyfile=None, ca_certs=None)
smtp_spec="""
[smtp]
host = string(default='localhost')
port = integer(default=587)
user = string
password = string
tls = boolean(default=True)
certfile = string
keyfile = string
ca_certs = string
"""

def smtp_init(config):
    cfg = smtp_defaults.copy()
    cfg.update(config)
    return SMTPOutput(host=cfg['host'],port=cfg['port'],
        user=cfg['user'].encode('ascii'),password=cfg['password'].encode('ascii'),
        tls=cfg['tls'],certfile=cfg['certfile'],keyfile=cfg['keyfile'],ca_certs=cfg['ca_certs'])

imap_defaults = dict(host='localhost', port=993, user=None, password=None, cram_md5=True,
        certfile=None, keyfile=None, ca_certs=None)
imap_spec="""
[imap]
host = string(default='localhost')
port = integer(default=993)
user = string
password = string
cram_md5 = boolean(default=True)
certfile = string
keyfile = string
ca_certs = string
"""

def imap_init(config, keep=False, filter=True):
    cfg = imap_defaults.copy()
    cfg.update(config)
    return IMAPSource(host=cfg['host'],port=cfg['port'],
        keyfile=cfg['keyfile'], certfile=cfg['certfile'], ca_certs=cfg['ca_certs'],
        user=cfg['user'],password=cfg['password'],cram_md5=cfg['cram_md5'],
        keep=keep,filter=filter)

def imap_same_login(a,b):
    "same config except for folder and keep"
    from ekklesia.data import objects_equal
    keys = ('host','port','login','cram_md5','keyfile','certfile','ca_certs')
    return objects_equal(a,b,keys)

class MessageSource(object):
    def __init__(self, keep=True, filter=True):
        self.keep = keep # keep processed messages?
        self.filter = filter # filter only unseen and flagged messages

    def __len__(self): return 0
    def open(self): return False
    def close(self): pass
    def __iter__(self): pass

class MessageOutput(object):
    def open(self): return False
    def close(self): pass
    def send(self,mail): raise NotImplementedError

import imaplib

class IMAPSource(MessageSource):

    def __init__(self, host="localhost",port=imaplib.IMAP4_SSL_PORT,
        certfile=None,keyfile=None,ca_certs=None,cert_reqs=None,
        user="",password="",cram_md5=True,keep=True,filter=True):
        from kryptomime.transport import IMAP4_TLS
        super(IMAPSource,self).__init__(keep,filter)
        self.imap = IMAP4_TLS(host=host,port=port,certfile=certfile,keyfile=keyfile,
            cert_reqs=cert_reqs,ca_certs=ca_certs)
        self.user = user
        self.password = password
        self.cram_md5 = cram_md5
        self.folder = None

    def open(self):
        if self.cram_md5:
            status, response = self.imap.login_cram_md5(self.user, self.password)
        else:
            status, response = self.imap.login(self.user, self.password) # plaintext
        if not status=='OK': return False
        return self.set_folder()

    def close(self):
        if not self.keep:
            status, response = self.imap.expunge()
        self.imap.logout()

    def set_folder(self,folder='INBOX'):
        status, response = self.imap.select(folder)
        if not status=='OK': return False
        self.folder = folder
        return True

    def __len__(self):
        status, response = self.imap.status(self.folder, "(UNSEEN)")
        if not status=='OK': return 0
        return int(response[0].split()[2].strip(').,]'))

    def __iter__(self):
        from kryptomime.mail import protect_mail
        filter = "(OR UNSEEN FLAGGED)" if self.filter else 'ALL'
        status, response = self.imap.uid('search', None, filter)
        if not status=='OK': return
        email_ids= response[0].split()
        for e_id in email_ids:
            status, response = self.imap.uid('fetch',e_id, '(FLAGS)')
            flags = ''
            for flag in imaplib.ParseFlags(response[0]):
                if 'Flagged' in flag: flags += 'F'
                elif 'Seen' in flag: flags += 'S'
                elif 'Deleted' in flag: flags += 'D'
            if 'D' in flags: continue
            # mark for processing
            status, response = self.imap.uid('store',e_id, '+FLAGS', r'(\Flagged)')
            status, response = self.imap.uid('fetch',e_id, '(RFC822)')
            raw = response[0][1]
            yield protect_mail(raw,sevenbit=False), flags
            if self.keep:
                status,response = self.imap.uid('store',e_id, '-FLAGS', r'(\Flagged)')
            else:
                status,response = self.imap.uid('store',e_id, '+FLAGS', r'(\Deleted)')

class SMTPOutput(MessageOutput):

    def __init__(self, host="localhost",port=587,user="",password="",
        tls=True,keyfile=None,certfile=None,ca_certs=None,cert_reqs=None):
        self.user = user
        self.password = password
        if tls:
            from kryptomime.transport import SMTP_TLS
            self.smtp = SMTP_TLS(host,port)
            self.smtp.starttls(keyfile=keyfile,certfile=certfile,cert_reqs=cert_reqs,ca_certs=ca_certs)
            self.smtp.ehlo()
        else:
            from smtplib import SMTP
            self.smtp = SMTP(host,port)

    def open(self):
        if not self.user: return True
        try: self.smtp.login(self.user, self.password)
        except: return False
        return True

    def close(self):
        self.smtp.quit()

    def send(self,msg):
        import email
        sender = msg['From']
        tos = msg.get_all('To',[])
        ccs = msg.get_all('CC',[])
        to = email.utils.getaddresses(tos + ccs)
        return not len(self.smtp.sendmail(sender, to, msg.as_string()))

class VirtualIMAP(MessageSource):

    def __init__(self, mailbox=None,keep=True,filter=True,readonly=False):
        super(VirtualIMAP,self).__init__(keep,filter)
        self.main = self.mailbox = mailbox
        self.readonly = readonly

    def __len__(self):
        from mailbox import Maildir
        count = 0
        haveflags = isinstance(self.mailbox,Maildir)
        for mail in list(self.mailbox.values()):
            if haveflags and 'S' in mail.get_flags(): continue
            count += 1
        return count

    def open(self): return True

    def close(self): self.mailbox.close()

    def set_folder(self,folder='INBOX'):
        from mailbox import Maildir, MH
        assert isinstance(self.main,(Maildir,MH)), "mailbox does not support folders"
        self.mailbox = self.main.get_folder(folder)
        return True

    def __iter__(self):
        from mailbox import Maildir
        from kryptomime.mail import protect_mail
        haveflags = isinstance(self.mailbox,Maildir)
        for key, mail in list(self.mailbox.items()):
            if haveflags:
                flags = mail.get_flags()
                if self.filter and 'S' in flags and not 'F' in flags: continue
                if not self.readonly:
                    mail.set_subdir('cur')
                    mail.add_flag('F')
            else: flags = ''
            if not self.readonly: self.mailbox[key] = mail
            yield protect_mail(mail,sevenbit=False),flags
            if self.readonly: continue
            if self.keep:
                if haveflags:
                    mail.remove_flag('F')
                    mail.add_flag('S')
                self.mailbox[key] = mail
            else: self.mailbox.remove(key) 

class VirtualMailServer(MessageOutput):
    def __init__(self, dir=''):
        import os
        super(VirtualMailServer,self).__init__()
        if dir and not os.path.exists(dir): os.makedirs(dir)
        self.dir = dir
        self.mailboxes = []
        self.accounts = {}

    def add_account(self,address,dir=None,keep=True,mboxtype=None):
        import os, mailbox
        if type(address)==str: address = [address]
        if not dir: dir = os.path.join(self.dir,address[0])
        for mbox in self.mailboxes:
            assert mbox._path != dir, "path already used by other mailbox"
        if not mboxtype: mboxtype = mailbox.Maildir
        factory = {mailbox.Maildir: mailbox.MaildirMessage,
                    mailbox.MH: mailbox.MHMessage, 
                    mailbox.mbox: mailbox.mbox}.get(mboxtype,None)
        mbox = mboxtype(dir,factory=factory,create=True)
        self.mailboxes.append(mbox)
        for a in address:
            assert a not in self.accounts,"account exists"
            self.accounts[a] = mbox
        return self.get_imap(address[0],keep=keep)

    def get_imap(self,address,keep=True,readonly=False):
        try: mailbox = self.accounts[address]
        except KeyError: return None
        return VirtualIMAP(mailbox=mailbox,keep=keep,readonly=readonly)

    def open(self): return True

    def close(self): pass

    def finish(self):
        for mbox in self.mailboxes: mbox.clean()

    def send(self,msg):
        import email
        from email.header import decode_header
        import smtplib
        tos = msg.get_all('to', []) + msg.get_all('cc', [])
        recipients = [email.utils.parseaddr(decode_header(to)[0][0])[1] for to in tos]
        errors = {}
        for to in recipients:
            if to in self.accounts:
                self.accounts[to].add(msg)
            else:
                errors[to] = 'user does not exist'
        if errors: raise smtplib.SMTPRecipientsRefused(errors)
        return True
