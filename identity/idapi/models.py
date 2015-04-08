# -*- coding: utf-8 -*-
#
# Models
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

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.db import models
from django.db.models.signals import post_save, post_delete
from django.dispatch.dispatcher import receiver
from django.db import transaction
from django.core.checks import register

from collections import OrderedDict
from django_extensions.db.fields import UUIDField
from jsonfield import JSONField

from accounts.models import Account

#-------------------------------------------------------------------------------------

from oauth2_provider.models import AbstractApplication
from oauth2_provider.generators import generate_client_secret
from oauth2_provider.validators import validate_uris

class IDApplication(AbstractApplication):
    """
    Custom Application model which adds permitted and auto-permitted scopes field
    """
    permitted_scopes = models.TextField('Scopes permitted for this application',blank=True)
    autopermit_scopes = models.TextField('Scopes automatically granted without consumer',blank=True)
    required_scopes = models.TextField('Scopes always required for this application',blank=True)

    push_uris = models.TextField(help_text=_("Push URIs list, space separated"),
                                     validators=[validate_uris], blank=True)
    push_secret = models.CharField(max_length=255, blank=True,
                                     default=generate_client_secret)
    two_factor_auth = models.NullBooleanField(_('Whether to require two factor authentication'), default=False, null=True)

#-------------------------------------------------------------------------------------

orderedJSON = {'object_pairs_hook': OrderedDict}

@register('idapi')
def check_shares(app_configs, **kwargs):
    return []

def notify_share(obj,action,connection=None):
    from accounts.models import send_broker_msg
    name = obj.share.name
    info = dict(share=name, no=obj.no, action=action)
    msg = dict(format='share',version=(1,0), change=[info])
    send_broker_msg(msg, settings.SHARE_EXCHANGE.format(name),connection=connection)

class Share(models.Model):
    name = models.CharField(_('share name'),max_length=30,unique=True)
    maxno = models.IntegerField(_('number of last object'),default=0,editable=False)
    version = models.IntegerField(_('current version'),default=0,editable=False)
    last_push = models.IntegerField(_('last push'),default=0,editable=False) # last pushed version
    last_modified = models.DateTimeField(_('last modified'), auto_now=True)
    #data = JSONField(_('share data'),blank=True,load_kwargs={'object_pairs_hook': OrderedDict})
    ref_counting = models.BooleanField(_('whether to delete an object only after all clients have seen/deleted it'), default=False)

    def __unicode__(self): return self.name

    def __len__(self):
        return self.objs.count()

    def next_version(self):
        with transaction.atomic():
            share = Share.objects.select_for_update().only('version').get(pk=self.pk)
            share.version += 1
            share.save(update_fields=('version',))
        return share.version

    def next_object(self):
        with transaction.atomic():
            share = Share.objects.select_for_update().only('version','maxno').get(pk=self.pk)
            share.version += 1
            share.maxno += 1
            share.save(update_fields=('version','maxno'))
        return share.maxno, share.version

class ShareObject(models.Model):
    class Meta:
        unique_together = ('share','no')
        verbose_name = _('share object')
        #ordering = ['no']
    share = models.ForeignKey(Share,related_name='objs') # on_delete=CASCADE
    no = models.IntegerField(_('id'),default=0,editable=False) # pk within share
    version = models.IntegerField(_('version'),editable=False) # version for last change
    last_modified = models.DateTimeField(_('last modified'), auto_now=True)
    last_client = models.ForeignKey(IDApplication,related_name='share_client',
         null=True, on_delete=models.SET_NULL) # last client which modified it
    data = JSONField(_('object data'),blank=True, null=True,load_kwargs=orderedJSON)

    def get_model_fields(self):
        fields = {}
        options = self._meta
        for field in sorted(options.concrete_fields + options.many_to_many + options.virtual_fields):
            fields[field.name] = getattr(self,field.name)
        return fields

    def save(self, *args, **kwargs):
        if not self.no:
            self.no, self.version = self.share.next_object()
        else:
            self.version = self.share.next_version()
        client = kwargs.get('client')
        if client:
            self.last_client = client
            del kwargs['client']
        super(ShareObject, self).save(*args, **kwargs) # Call the "real" save() method.

    def __unicode__(self):
        return "%s/%i" % (self.share.name,self.no)

    def delete(self, client=None, **kwargs):
        share = self.share
        if share.ref_counting and client:
            change = ShareChange(share=share, client=client, no=self.no, 
                version=share.version, action=ShareChange.SEEN)
        else:
            change = ShareChange(share=share, client=client, no=self.no,
                 version=self.share.next_version(), action=ShareChange.DELETE)
            notify_share(self,'delete')
        change.save()
        super(ShareObject,self).delete(**kwargs)

class ShareChange(models.Model):
    DELETE = 0
    CREATE = 1
    MODIFY = 2
    SEEN = 3
    ACTION_CHOICES = (
        (DELETE, 'delete'),
        (CREATE, 'create'),
        (MODIFY, 'modify'),
        (SEEN,   'seen'),
    )

    share = models.ForeignKey(Share,related_name='changes') # on_delete=CASCADE
    no = models.IntegerField(_('id'),default=0,editable=False) # pk within share
    version = models.IntegerField(_('version'),editable=False) # version of the change
    time = models.DateTimeField(_('last_change'), default=timezone.now)
    action = models.PositiveIntegerField(_('action'),choices=ACTION_CHOICES,default=CREATE)
    client = models.ForeignKey(IDApplication,related_name='share_changes',
         null=True, on_delete=models.SET_NULL)

    def __unicode__(self):
         return "%s/%i:%i" % (self.share.name,self.no,self.version)

@receiver(post_save, sender=ShareObject)
def _share_object_save(sender, instance, created, raw, **kwargs):
    if raw:
        #print "fixture %s" % instance
        return
    #print "saved %s" % instance
    change = ShareChange(share=instance.share, no=instance.no, version=instance.version,
        time=instance.last_modified, client=instance.last_client,
        action=ShareChange.CREATE if created else ShareChange.MODIFY)
    change.save()
    notify_share(instance,'create' if created else 'modify')

#-------------------------------------------------------------------------------------

class ApplicationUUID(models.Model):
    application = models.ForeignKey(IDApplication,related_name='app_uuids') # on_delete=CASCADE
    user = models.ForeignKey(Account,related_name='app_uuids') # on_delete=CASCADE
    uuid = UUIDField(_('Application-specific member UUID'),unique=True,db_index=True)

    def __unicode__(self): return self.uuid

def get_auid(application,user):
    auid, created = ApplicationUUID.objects.get_or_create(user=user,application=application,
            defaults={'user':user,'application':application})
    return auid

#-------------------------------------------------------------------------------------

def notify_list(list_,action,connection=None):
    from accounts.models import send_broker_msg
    info = dict(list=list_, action=action)
    msg = dict(format='list',version=(1,0), change=[info])
    send_broker_msg(msg, settings.LIST_EXCHANGE,connection=connection)

@register('idapi')
def check_lists(app_configs, **kwargs):
    return []

class UserList(models.Model):
    ulid = UUIDField('list UUID',unique=True,db_index=True)
    name = models.CharField(max_length=50,blank=True)
    info = JSONField(_('list info'),blank=True, null=True,load_kwargs=orderedJSON)
    owner = models.ForeignKey(IDApplication,related_name='app_lists',null=True) # on_delete=CASCADE
    listmembers = models.ManyToManyField(Account,through="UserListMember",symmetrical=False,related_name='listmember')

    maxno = models.IntegerField(_('number of last member'),default=0,editable=False)
    version = models.IntegerField(_('current version'),default=0,editable=False)
    last_push = models.IntegerField(_('last push'),default=0,editable=False) # last pushed version
    last_modified = models.DateTimeField(_('last modified'), auto_now=True)

    def __unicode__(self): return self.name

    def __len__(self):
        return self.members.count()

    def next_version(self):
        with transaction.atomic():
            ulist = UserList.objects.select_for_update().only('version').get(pk=self.pk)
            ulist.version += 1
            ulist.save(update_fields=('version',))
        return ulist.version

    def next_user(self):
        with transaction.atomic():
            ulist = UserList.objects.select_for_update().only('version','maxno').get(pk=self.pk)
            ulist.version += 1
            ulist.maxno += 1
            ulist.save(update_fields=('version','maxno'))
        return ulist.maxno, ulist.version

    def skip_user(self):
        with transaction.atomic():
            ulist = UserList.objects.select_for_update().only('maxno').get(pk=self.pk)
            ulist.maxno += 1
            ulist.save(update_fields=('maxno',))
        return ulist.maxno

    def is_member(self,user):
        return self.members.filter(member=user.pk).exists()

    def get_all(self):
        return self.members.order_by('no')

class UserListMember(models.Model):
    class Meta:
        unique_together = (('userlist','no'),('userlist','member'))
        #unique_together = (('userlist','member'),)
        #index_together = (('userlist','no'),)
        ordering = ['no']
    userlist = models.ForeignKey(UserList,related_name='members') # on_delete=CASCADE
    member = models.ForeignKey(Account,related_name='lists') # on_delete=CASCADE
    no = models.IntegerField(_('position'),default=0,editable=False) # pk within list

    def save(self, *args, **kwargs):
        if not self.no: self.no = self.userlist.next_user()[0]
        super(UserListMember, self).save(*args, **kwargs) # Call the "real" save() method.

class Message(models.Model):
    FAILED = -3
    NOCRYPTO = -2
    DELAYED = -1
    UNKNOWN = 0
    QUEUED = 1
    SENT = 2
    OK = 3
    STATUS_CHOICES = (
        (FAILED, 'failed'),
        (NOCRYPTO, 'encryption failed'),
        (DELAYED, 'delayed'),
        (UNKNOWN, 'unknown'),
        (QUEUED, 'queued'),
        (SENT, 'sent'),
        (OK, 'ok'),
    )
    user = models.ForeignKey(Account,related_name='messages')
    application = models.ForeignKey(IDApplication,related_name='app_messages',null=True)
    identity = models.CharField(_('assigned identity for the application'),max_length=30)
    outgoing = models.BooleanField(_('whether the message is outgoing, otherwise incoming'), default=True)
    crypto = models.BooleanField(_('whether the message needs to be encrypted/decrypted'), default=False)
    email = models.BooleanField(_('whether the message is an email'), default=True)
    status = models.IntegerField(_('status code'),choices=STATUS_CHOICES,default=QUEUED)
    time = models.DateTimeField(_('time send/received'), default=timezone.now)
    locked = models.DateTimeField(_('when the message has been locked'), default=None, null=True)
    data = JSONField(_('message data'))

#-------------------------------------------------------------------------------------

class PublicKey(models.Model):
    NONE = 0
    PGP = 1
    X509 = 2
    KEY_CHOICES = (
        (NONE, 'none'),
        (PGP, 'PGP'),
        (X509, 'X.509'),
    )
    DELETED = 0
    UNCONFIRMED = 1
    CONFIRMED = 2
    TRUSTED = 3
    TRUST_CHOICES = (
        (DELETED, 'deleted'),
        (UNCONFIRMED, 'unconfirmed'),
        (CONFIRMED, 'confirmed'),
        (TRUSTED, 'trusted'),
    )
    TRUST_LUT = dict(i[::-1] for i in TRUST_CHOICES)
    # unique = user,active
    user = models.ForeignKey(Account,related_name='publickeys')
    keytype = models.PositiveIntegerField(_('key type'),choices=KEY_CHOICES,default=PGP)
    trust = models.PositiveIntegerField(_('key trust'),choices=TRUST_CHOICES,default=UNCONFIRMED)
    expires = models.DateTimeField(_('expiration date'), blank=True, null=True)
    active = models.BooleanField(_('whether this is the active key for the user'), default=False)
    fingerprint = models.CharField(_('fingerprint'),max_length=64) # sha1=40, sha256=64
    data = JSONField(_('key data'),blank=True, null=True)
    # keydata = ascii/base64, confirmcode=string (if unconfirmed), identities=[emails]
