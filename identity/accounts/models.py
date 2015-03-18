# -*- coding: utf-8 -*-
#
# Models
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

import re
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.core import validators
from django.utils import timezone
from django.contrib.auth.models import UserManager, AbstractBaseUser, PermissionsMixin
from django.db import models, transaction
from django.utils.decorators import method_decorator
from django.core.exceptions import ValidationError
from django.template.loader import render_to_string

from django_extensions.db.fields import UUIDField
from mptt.models import MPTTModel, TreeForeignKey, TreeManyToManyField

from django_countries.fields import CountryField
#from phonenumber_field.modelfields import PhoneNumberField
from ekklesia.models import ModelDiffMixin

def send_broker_msg(msg, exchange, queue, connection=None):
    if not settings.BROKER_URL: return
    from kombu import Connection, Exchange, Queue, Producer
    exchange = Exchange(exchange, 'fanout')
    queue = Queue(queue, exchange=exchange)
    print 'sending msg', msg
    if connection:
        conn.Producer(serializer='json').publish(msg, exchange=exchange, declare=[queue])
        return
    if settings.USE_CELERY:
        import celery
        conn_context = celery.current_app.pool.acquire(timeout=1)
    else:
        conn_context = Connection(settings.BROKER_URL,ssl=settings.BROKER_USE_SSL)
    with conn_context as conn:
        conn.Producer(serializer='json').publish(msg, exchange=exchange, declare=[queue])

def notify_backends(status,uuid):
    msg = dict(format='member',version=(1,0),status=status,uuid=uuid)
    send_broker_msg(msg, settings.BACKEND_EXCHANGE, settings.BACKEND_QUEUE)

#-------------------------------------------------------------------------------------

class NestedGroup(MPTTModel,ModelDiffMixin):
    syncid = models.PositiveIntegerField(_('Nested group sync id'),unique=True,blank=True,null=True)
    name = models.CharField(max_length=50,unique=True,blank=True,null=True)
    parent = TreeForeignKey('self', null=True, blank=True, related_name='children')
        #limit_choices_to={'depth__gt':models.F('parent__depth')})
    depth = models.PositiveIntegerField(blank=True,null=True) # 0=empty, 1=country,2=state,3=region,4=city,5=suburb
    description = models.TextField(_('Description of the nested group'),blank=True)
    #is_fixed = models.BooleanField(_('whether the nested group may be modified'), default=True,
    #    help_text=_('Designates whether the nested group may be modified by apps and is not predetermined'))
    class MPTTMeta:
        order_insertion_by = ['name']
        level_attr = 'mptt_level'
    def __unicode__(self): return self.name

    def clean(self):
        if not self.parent: return
        pdepth = self.parent.depth
        if not pdepth: return
        if not self.depth: self.depth = pdepth+1
        elif self.depth <= pdepth:
            raise ValidationError('Depth must be larger then parent.')

    def merge_with(self,target):
        """merge this nested group into its parent or a sibling and update all users."""
        # update users to target
        assert self.parent == target or self.get_siblings().filter(pk=target).exists(), "cannot merge"
        Account.objects.filter(department=self).update(department=target)
        for child in self.get_children(): child.moveto(target)
        self.delete()

#-------------------------------------------------------------------------------------

class AccountManager(UserManager):
    def create_superuser(self, username, password, **extra_fields):
        return super(AccountManager,self).create_superuser(username, '', password,
                status = self.model.SYSTEM, **extra_fields)

class Account(AbstractBaseUser, PermissionsMixin, ModelDiffMixin):
    """
    Implementing a fully featured User model with admin-compliant permissions.
    Username and password are required. Other fields are optional. Emails must be unique.
    inherited: password, last_login, is_superuser, groups, user_permissions
    """

    # Django User class equivalents
    username = models.CharField(_('username'), max_length=30, unique=True,
        help_text=_('Required. 30 characters or fewer. Letters, numbers and '
                    '@/./+/-/_ characters'),
        validators=[
            validators.RegexValidator(re.compile('^[\w.@+-]+$'), _('Enter a valid username.'), 'invalid')
        ])
    email = models.EmailField(_('email address'), blank=True, null=True, unique=True, default=None)
    is_staff = models.BooleanField(_('staff status'), default=False,
        help_text=_('Designates whether the user can log into this admin '
                    'site.'))
    is_active = models.BooleanField(_('active'), default=True,
        help_text=_('Designates whether this user should be treated as '
                    'active. Unselect this instead of deleting accounts.'))
    date_joined = models.DateTimeField(_('date joined'), auto_now_add=True,)

    objects = AccountManager() # differs from django User class

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = [] # differs from django User class

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def get_absolute_url(self):
        from django.utils.http import urlquote
        return "/user/%s/" % urlquote(self.username)

    def get_full_name(self):
        return self.username

    def get_short_name(self):
        return self.username

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        from django.core.mail import send_mail
        send_mail(subject, message, from_email, [self.email])

    #-----------------------------------------------------------------------
    # extensions to User
    DELETED = 0
    SYSTEM = 1
    GUEST = 2
    MEMBER = 3
    ELIGIBLE = 4
    NEWMEMBER = 5
    STATUS_CHOICES = (
        (DELETED, 'deleted'),
        (SYSTEM, 'system user'),
        (GUEST, 'guest'),
        (MEMBER, 'plain member'),
        (ELIGIBLE, 'eligible member'),
        (NEWMEMBER, 'new member'),
    )

    status = models.PositiveIntegerField(_('user status'),choices=STATUS_CHOICES,default=GUEST)
    uuid = UUIDField(_('Member UUID'),unique=True,auto=False,blank=True,null=True) # for sync with external DB, empty if non-member
    nested_groups = TreeManyToManyField('NestedGroup',blank=True,null=True, verbose_name=_('nested groups the users belongs to'))

    verified_by = models.ManyToManyField("self",through="Verification",symmetrical=False,related_name='has_verified')
    verified = models.BooleanField(_('verified'), default=False,
        help_text=_('Designates whether the identify has been verified.'))

    # optional stuff
    staff_notes = models.TextField(_('notes by staff'), blank=True)
    # to be verified, emptied when verified
    public_id = models.TextField(_('unverified public identity'), max_length=128, blank=True, null=True)
    profile = models.TextField(_('unverified personal profile'), blank=True, null=True)
    fingerprint = models.CharField(_('unverified public key fingerprint'),max_length=40, blank=True, null=True)
    avatar = models.ImageField(_('user avatar'), blank=True,null=True,upload_to='avatars')

    secure_email = models.BooleanField(_('secure email'), default=False,
        help_text=_('Designates whether the email address is not stored locally.'))

    two_factor_auth = models.NullBooleanField(_('whether to two factor authentication'), default=False)
    notify_login = models.BooleanField(_('notify after login'), default=False,
        help_text=_('Designates whether a notification email is sent after every succesful login.'))

    def is_member(self):
        return self.status in (self.MEMBER,self.ELIGIBLE)
    is_member.short_description = 'Member account'

    def is_identity_verified(self,count=2):
        return self.verified or self.verifications.filter(identity=True).values('verifier').distinct().count() >= count
    is_identity_verified.short_description = 'Identity verified'

    def is_public_id_verified(self):
        return self.verifications.exclude(public_id=u'').count() > 0
    is_public_id_verified.short_description = 'Public ID verified'

    def is_profile_verified(self):
        return self.verifications.exclude(profile=u'').count() > 0
    is_profile_verified.short_description = 'Profile verified'

    def is_publickey_verified(self):
        return self.verifications.exclude(public_key=u'').count() > 0
    is_publickey_verified.short_description = 'Public key verified'

    def get_nested_groups(self,parents=False):
        if not parents: return self.nested_groups.all()
        return set([g for ngroup in self.nested_groups.all() for g in ngroup.get_ancestors(include_self=True)])

    def get_verified_profile(self):
        ver = self.verifications.exclude(profile=u'')
        if not ver.count(): return None
        return ver.latest('date_verified').profile

    def get_verified_public_id(self):
        ver = self.verifications.exclude(public_id=u'')
        if not ver.count(): return None
        return ver.latest('date_verified').public_id

    def convert_to_member(self):
        if self.__class__==Account: return self
        from django.db import connection
        member = self.account_ptr
        if member.status == self.GUEST:
            member.status = self.MEMBER
            member.save(update_fields=('status',))
        cursor = connection.cursor()
        cursor.execute("DELETE FROM %s WHERE account_ptr_id = %s" % (self._meta.db_table, member.id))
        transaction.commit_unless_managed()
        return member

    def convert_to_guest(self):
        guest = Guest(account_ptr=self,status = self.GUEST)
        guest.save_base(raw=True)
        return Guest.objects.get(pk=guest.pk)

    def convert_to_verifier(self):
        target = self.nested_groups.exclude(syncid=None).first()
        verifier = Verifier(account_ptr=self,for_nested_groups = target)
        verifier.save_base(raw=True)
        return Verifier.objects.get(pk=verifier.pk)

    def email_confirmed(self, email):
        self.email = email
        #user.is_active = True
        if self.status == self.NEWMEMBER:
            notify_backends(status='registering',uuid=self.uuid)
        self.save(update_fields=('email',))

class Verifier(Account):
    parent = models.ForeignKey(Account,related_name='+',blank=True,null=True)
    for_nested_groups = models.ForeignKey(NestedGroup,blank=True,null=True)
    delegation = models.IntegerField(_('level of subdelegation possible'),default=0)
    expires = models.DateTimeField(_('date of expiration'), blank=True, null=True)

class Guest(Account):
    # full name and postal code are mandatory
    first_name = models.CharField(_('first name'), max_length=30)
    last_name = models.CharField(_('last name'), max_length=30)
    address = models.CharField(_('street/no or POBox'),max_length=50)
    address_prefix = models.CharField(max_length=50,blank=True)
    city = models.CharField(max_length=30)
    postal_code = models.PositiveIntegerField(_('postal code'))
    country = CountryField(_("Country"),default='DE')
    #phone = PhoneNumberField(_("Phone number"),blank=True)

    def __unicode__(self):
        return '%s %s %s' % (self.email,self.postal_code,self.city)

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name

class Verification(models.Model):
    # todo rename to verified_by
    user = models.ForeignKey(Account,related_name='verifications',on_delete=models.PROTECT)
    verifier = models.ForeignKey(Account,related_name='+',on_delete=models.PROTECT)
    date_verified = models.DateTimeField(_('date verified'), default=timezone.now)
    identity = models.NullBooleanField(_('identity verified'), blank=True)
    public_id = models.TextField(_('verified public identity'), max_length=128, blank=True)
    profile = models.TextField(_('verified personal information'), blank=True)
    fingerprint = models.CharField(_('verified public key fingerprint'),max_length=40, blank=True)

    def clean(self):
        if self.user == self.verifier:
            raise ValidationError('User and verifier must not be the same.')

class Invitation(models.Model, ModelDiffMixin):
    """Invitation model"""
    DELETED = 0
    NEW = 1
    REGISTERED = 2
    FAILED = 3
    REGISTERING = 4
    STATUS_CHOICES = (
        (DELETED, 'deleted'),
        (NEW, 'new'),
        (REGISTERED, 'registered'),
        (FAILED, 'failed'),
        (REGISTERING, 'registering'),
    )

    status = models.PositiveIntegerField(_('user type'),choices=STATUS_CHOICES,default=NEW)
    code = models.CharField(_('invitation code'),max_length=36, unique=True)
    uuid = UUIDField(_('member UUID'),unique=True,blank=True,null=True,auto=False)
    secret = models.CharField(_('secret'), blank=True, null=True, max_length=128)

    def registration_failed(self):
        self.status = self.FAILED
        self.secret = None
        self.save(update_fields=('status','secret'))

# inspired by django-registrations

SHA1_RE = re.compile('^[a-f0-9]{40}$')

class ConfirmationManager(models.Manager):
    def confirm(self, confirmation_key):
        if not SHA1_RE.search(confirmation_key): return False
        try:
            confirmation = self.get(confirmation_key=confirmation_key)
        except self.model.DoesNotExist:
            return False
        if not confirmation.confirmation_key_expired():
            user = confirmation.user
            user.email_confirmed(confirmation.email)
            confirmation.delete()
            return user
        confirmation.confirmation_failed()
        return False

    def create_confirmation(self, user, email):
        import hashlib, random
        salt = hashlib.sha1( str(random.random()).encode('ascii') ).hexdigest()[:5]
        token = salt+user.username
        confirmation_key = hashlib.sha1(token.encode('ascii')).hexdigest()
        return self.create(user=user, confirmation_key=confirmation_key, email=email)

    def delete_expired(self):
        for confirmation in self.all():
            if confirmation.confirmation_key_expired():
                confirmation.confirmation_failed()

class EMailConfirmation(models.Model):
    user = models.OneToOneField(Account, primary_key=True, 
        verbose_name=_('user'), related_name='email_unconfirmed')
    email = models.EmailField(_('email address'), unique=True)
    confirmation_key = models.CharField(_('confirmation key'), max_length=40)
    created = models.DateTimeField(_('date created'), auto_now_add=True,)

    objects = ConfirmationManager()

    class Meta:
        verbose_name = _('E-Mail confirmation')
        verbose_name_plural = _('E-Mail confirmation')

    def __unicode__(self):
        return u"E-Mail confirmation for %s" % self.user

    def confirmation_key_expired(self):
        import datetime
        from django.utils import timezone
        expiration_date = datetime.timedelta(days=settings.EMAIL_CONFIRMATION_DAYS)
        return self.created + expiration_date <= timezone.now()
    confirmation_key_expired.boolean = True

    def confirmation_failed(self):
        user = self.user
        self.delete()
        if not user.is_active and not user.email:
            user.delete()
        try:
            invitation = Invitation.objects.get(uuid=user.uuid,status=Invitation.REGISTERING)
            invitation.registration_failed()
        except: pass

    def send_confirmation_email(self, domain, use_https=False):
        from django.core.mail import send_mail
        from django.core.urlresolvers import reverse
        ctx_dict = {
            'confirmation_key': self.confirmation_key,
            'expiration_days': settings.EMAIL_CONFIRMATION_DAYS,
            'domain': domain,
            'protocol': 'https' if use_https else 'http',
        }
        subject = render_to_string('registration/confirmation_email_subject.txt',
                                   ctx_dict)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())

        message = render_to_string('registration/confirmation_email.txt',
                                   ctx_dict)

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [self.email])
