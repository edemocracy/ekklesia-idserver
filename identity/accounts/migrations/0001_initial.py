# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import accounts.models
import re
import django_countries.fields
import django_extensions.db.fields
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0006_require_contenttypes_0002'),
    ]

    operations = [
        migrations.CreateModel(
            name='Account',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(null=True, verbose_name='last login', blank=True)),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(help_text='Required. 30 characters or fewer. Letters, numbers and @/./+/-/_ characters', unique=True, max_length=30, verbose_name='username', validators=[django.core.validators.RegexValidator(re.compile(b'^[\\w.@+-]+$'), 'Enter a valid username.', b'invalid')])),
                ('email', models.EmailField(null=True, default=None, max_length=254, blank=True, unique=True, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(auto_now_add=True, verbose_name='date joined')),
                ('status', models.PositiveIntegerField(default=2, verbose_name='user status', choices=[(0, b'deleted'), (1, b'system user'), (2, b'guest'), (3, b'plain member'), (4, b'eligible member'), (5, b'new member')])),
                ('uuid', django_extensions.db.fields.UUIDField(auto=False, unique=True, null=True, verbose_name='Member UUID', blank=True)),
                ('verified', models.BooleanField(default=False, help_text='Designates whether the identify has been verified.', verbose_name='verified')),
                ('staff_notes', models.TextField(verbose_name='notes by staff', blank=True)),
                ('public_id', models.TextField(max_length=128, null=True, verbose_name='unverified public identity', blank=True)),
                ('profile', models.TextField(null=True, verbose_name='unverified personal profile', blank=True)),
                ('fingerprint', models.CharField(max_length=40, null=True, verbose_name='unverified public key fingerprint', blank=True)),
                ('avatar', models.ImageField(upload_to=b'avatars', null=True, verbose_name='user avatar', blank=True)),
                ('secure_email', models.BooleanField(default=False, help_text='Designates whether the email address is not stored locally.', verbose_name='secure email')),
                ('two_factor_auth', models.NullBooleanField(default=False, verbose_name='whether to two factor authentication')),
                ('notify_login', models.BooleanField(default=False, help_text='Designates whether a notification email is sent after every succesful login.', verbose_name='notify after login')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
            },
            managers=[
                ('objects', accounts.models.AccountManager()),
            ],
        ),
        migrations.CreateModel(
            name='Invitation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('status', models.PositiveIntegerField(default=1, verbose_name='user type', choices=[(0, b'deleted'), (1, b'new'), (2, b'registered'), (3, b'failed'), (4, b'registering')])),
                ('code', models.CharField(unique=True, max_length=36, verbose_name='invitation code')),
                ('uuid', django_extensions.db.fields.UUIDField(auto=False, unique=True, null=True, verbose_name='member UUID', blank=True)),
                ('secret', models.CharField(max_length=128, null=True, verbose_name='secret', blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='NestedGroup',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('path', models.CharField(unique=True, max_length=255)),
                ('depth', models.PositiveIntegerField()),
                ('numchild', models.PositiveIntegerField(default=0)),
                ('syncid', models.PositiveIntegerField(unique=True, null=True, verbose_name='Nested group sync id', blank=True)),
                ('name', models.CharField(max_length=50, unique=True, null=True, blank=True)),
                ('level', models.PositiveIntegerField(null=True, blank=True)),
                ('description', models.TextField(verbose_name='Description of the nested group', blank=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Verification',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('date_verified', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date verified')),
                ('identity', models.NullBooleanField(verbose_name='identity verified')),
                ('public_id', models.TextField(max_length=128, verbose_name='verified public identity', blank=True)),
                ('profile', models.TextField(verbose_name='verified personal information', blank=True)),
                ('fingerprint', models.CharField(max_length=40, verbose_name='verified public key fingerprint', blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='EMailConfirmation',
            fields=[
                ('user', models.OneToOneField(related_name='email_unconfirmed', primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL, verbose_name='user')),
                ('email', models.EmailField(unique=True, max_length=254, verbose_name='email address')),
                ('confirmation_key', models.CharField(max_length=40, verbose_name='confirmation key')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='date created')),
            ],
            options={
                'verbose_name': 'E-Mail confirmation',
                'verbose_name_plural': 'E-Mail confirmation',
            },
        ),
        migrations.CreateModel(
            name='Guest',
            fields=[
                ('account_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('first_name', models.CharField(max_length=30, verbose_name='first name')),
                ('last_name', models.CharField(max_length=30, verbose_name='last name')),
                ('address', models.CharField(max_length=50, verbose_name='street/no or POBox')),
                ('address_prefix', models.CharField(max_length=50, blank=True)),
                ('city', models.CharField(max_length=30)),
                ('postal_code', models.PositiveIntegerField(verbose_name='postal code')),
                ('country', django_countries.fields.CountryField(default=b'DE', max_length=2, verbose_name='Country')),
            ],
            options={
                'abstract': False,
            },
            bases=('accounts.account',),
        ),
        migrations.CreateModel(
            name='Verifier',
            fields=[
                ('account_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('delegation', models.IntegerField(default=0, verbose_name='level of subdelegation possible')),
                ('expires', models.DateTimeField(null=True, verbose_name='date of expiration', blank=True)),
                ('for_nested_groups', models.ForeignKey(blank=True, to='accounts.NestedGroup', null=True)),
            ],
            options={
                'abstract': False,
            },
            bases=('accounts.account',),
        ),
        migrations.AddField(
            model_name='verification',
            name='user',
            field=models.ForeignKey(related_name='verifications', on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='verification',
            name='verifier',
            field=models.ForeignKey(related_name='+', on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='account',
            name='groups',
            field=models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Group', blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', verbose_name='groups'),
        ),
        migrations.AddField(
            model_name='account',
            name='nested_groups',
            field=models.ManyToManyField(to='accounts.NestedGroup', verbose_name='nested groups the users belongs to', blank=True),
        ),
        migrations.AddField(
            model_name='account',
            name='user_permissions',
            field=models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Permission', blank=True, help_text='Specific permissions for this user.', verbose_name='user permissions'),
        ),
        migrations.AddField(
            model_name='account',
            name='verified_by',
            field=models.ManyToManyField(related_name='has_verified', through='accounts.Verification', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='verifier',
            name='parent',
            field=models.ForeignKey(related_name='+', blank=True, to=settings.AUTH_USER_MODEL, null=True),
        ),
    ]
