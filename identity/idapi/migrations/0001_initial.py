# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import django_extensions.db.fields
import jsonfield.fields
import oauth2_provider.validators
import oauth2_provider.generators
import django.utils.timezone
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ApplicationUUID',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', django_extensions.db.fields.UUIDField(editable=False, blank=True, unique=True, verbose_name='Application-specific member UUID', db_index=True)),
            ],
        ),
        migrations.CreateModel(
            name='IDApplication',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('client_id', models.CharField(default=oauth2_provider.generators.generate_client_id, unique=True, max_length=100, db_index=True)),
                ('redirect_uris', models.TextField(help_text='Allowed URIs list, space separated', blank=True, validators=[oauth2_provider.validators.validate_uris])),
                ('client_type', models.CharField(max_length=32, choices=[('confidential', 'Confidential'), ('public', 'Public')])),
                ('authorization_grant_type', models.CharField(max_length=32, choices=[('authorization-code', 'Authorization code'), ('implicit', 'Implicit'), ('password', 'Resource owner password-based'), ('client-credentials', 'Client credentials')])),
                ('client_secret', models.CharField(default=oauth2_provider.generators.generate_client_secret, max_length=255, db_index=True, blank=True)),
                ('name', models.CharField(max_length=255, blank=True)),
                ('skip_authorization', models.BooleanField(default=False)),
                ('permitted_scopes', models.TextField(verbose_name=b'Scopes permitted for this application', blank=True)),
                ('autopermit_scopes', models.TextField(verbose_name=b'Scopes automatically granted without consumer', blank=True)),
                ('required_scopes', models.TextField(verbose_name=b'Scopes always required for this application', blank=True)),
                ('push_uris', models.TextField(help_text='Push URIs list, space separated', blank=True, validators=[oauth2_provider.validators.validate_uris])),
                ('push_secret', models.CharField(default=oauth2_provider.generators.generate_client_secret, max_length=255, blank=True)),
                ('two_factor_auth', models.NullBooleanField(default=False, verbose_name='Whether to require two factor authentication')),
                ('keep_login', models.BooleanField(default=False, verbose_name=b'Whether to keep the user logged in')),
                ('user', models.ForeignKey(related_name='idapi_idapplication', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('identity', models.CharField(max_length=30, verbose_name='assigned identity for the application')),
                ('outgoing', models.BooleanField(default=True, verbose_name='whether the message is outgoing, otherwise incoming')),
                ('crypto', models.BooleanField(default=False, verbose_name='whether the message needs to be encrypted/decrypted')),
                ('email', models.BooleanField(default=True, verbose_name='whether the message is an email')),
                ('status', models.IntegerField(default=1, verbose_name='status code', choices=[(-3, b'failed'), (-2, b'encryption failed'), (-1, b'delayed'), (0, b'unknown'), (1, b'queued'), (2, b'sent'), (3, b'ok')])),
                ('time', models.DateTimeField(default=django.utils.timezone.now, verbose_name='time send/received')),
                ('locked', models.DateTimeField(default=None, null=True, verbose_name='when the message has been locked')),
                ('data', jsonfield.fields.JSONField(verbose_name='message data')),
                ('application', models.ForeignKey(related_name='app_messages', to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL, null=True)),
                ('user', models.ForeignKey(related_name='messages', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PublicKey',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('keytype', models.PositiveIntegerField(default=1, verbose_name='key type', choices=[(0, b'none'), (1, b'PGP'), (2, b'X.509')])),
                ('trust', models.PositiveIntegerField(default=1, verbose_name='key trust', choices=[(0, b'deleted'), (1, b'unconfirmed'), (2, b'confirmed'), (3, b'trusted')])),
                ('expires', models.DateTimeField(null=True, verbose_name='expiration date', blank=True)),
                ('active', models.BooleanField(default=False, verbose_name='whether this is the active key for the user')),
                ('fingerprint', models.CharField(max_length=64, verbose_name='fingerprint')),
                ('data', jsonfield.fields.JSONField(null=True, verbose_name='key data', blank=True)),
                ('user', models.ForeignKey(related_name='publickeys', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Share',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=30, verbose_name='share name')),
                ('maxno', models.IntegerField(default=0, verbose_name='number of last object', editable=False)),
                ('version', models.IntegerField(default=0, verbose_name='current version', editable=False)),
                ('last_push', models.IntegerField(default=0, verbose_name='last push', editable=False)),
                ('last_modified', models.DateTimeField(auto_now=True, verbose_name='last modified')),
                ('ref_counting', models.BooleanField(default=False, verbose_name='whether to delete an object only after all clients have seen/deleted it')),
            ],
        ),
        migrations.CreateModel(
            name='ShareChange',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('no', models.IntegerField(default=0, verbose_name='id', editable=False)),
                ('version', models.IntegerField(verbose_name='version', editable=False)),
                ('time', models.DateTimeField(default=django.utils.timezone.now, verbose_name='last_change')),
                ('action', models.PositiveIntegerField(default=1, verbose_name='action', choices=[(0, b'delete'), (1, b'create'), (2, b'modify'), (3, b'seen')])),
                ('client', models.ForeignKey(related_name='share_changes', on_delete=django.db.models.deletion.SET_NULL, to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL, null=True)),
                ('share', models.ForeignKey(related_name='changes', to='idapi.Share')),
            ],
        ),
        migrations.CreateModel(
            name='ShareObject',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('no', models.IntegerField(default=0, verbose_name='id', editable=False)),
                ('version', models.IntegerField(verbose_name='version', editable=False)),
                ('last_modified', models.DateTimeField(auto_now=True, verbose_name='last modified')),
                ('data', jsonfield.fields.JSONField(null=True, verbose_name='object data', blank=True)),
                ('last_client', models.ForeignKey(related_name='share_client', on_delete=django.db.models.deletion.SET_NULL, to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL, null=True)),
                ('share', models.ForeignKey(related_name='objs', to='idapi.Share')),
            ],
            options={
                'verbose_name': 'share object',
            },
        ),
        migrations.CreateModel(
            name='UserList',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('ulid', django_extensions.db.fields.UUIDField(editable=False, blank=True, unique=True, verbose_name=b'list UUID', db_index=True)),
                ('name', models.CharField(max_length=50, blank=True)),
                ('info', jsonfield.fields.JSONField(null=True, verbose_name='list info', blank=True)),
                ('maxno', models.IntegerField(default=0, verbose_name='number of last member', editable=False)),
                ('version', models.IntegerField(default=0, verbose_name='current version', editable=False)),
                ('last_push', models.IntegerField(default=0, verbose_name='last push', editable=False)),
                ('last_modified', models.DateTimeField(auto_now=True, verbose_name='last modified')),
            ],
        ),
        migrations.CreateModel(
            name='UserListMember',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('no', models.IntegerField(default=0, verbose_name='position', editable=False)),
                ('member', models.ForeignKey(related_name='lists', to=settings.AUTH_USER_MODEL)),
                ('userlist', models.ForeignKey(related_name='members', to='idapi.UserList')),
            ],
            options={
                'ordering': ['no'],
            },
        ),
        migrations.AddField(
            model_name='userlist',
            name='listmembers',
            field=models.ManyToManyField(related_name='listmember', through='idapi.UserListMember', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='userlist',
            name='owner',
            field=models.ForeignKey(related_name='app_lists', to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL, null=True),
        ),
        migrations.AddField(
            model_name='applicationuuid',
            name='application',
            field=models.ForeignKey(related_name='app_uuids', to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL),
        ),
        migrations.AddField(
            model_name='applicationuuid',
            name='user',
            field=models.ForeignKey(related_name='app_uuids', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterUniqueTogether(
            name='userlistmember',
            unique_together=set([('userlist', 'member'), ('userlist', 'no')]),
        ),
        migrations.AlterUniqueTogether(
            name='shareobject',
            unique_together=set([('share', 'no')]),
        ),
    ]
