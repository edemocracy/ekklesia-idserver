# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django_countries.fields


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_auto_20170801_0948'),
    ]

    operations = [
        migrations.AlterField(
            model_name='guest',
            name='address',
            field=models.CharField(max_length=50, null=True, verbose_name='street/no or POBox', blank=True),
        ),
        migrations.AlterField(
            model_name='guest',
            name='address_prefix',
            field=models.CharField(max_length=50, null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='guest',
            name='city',
            field=models.CharField(max_length=30, null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='guest',
            name='country',
            field=django_countries.fields.CountryField(default=b'DE', max_length=2, null=True, verbose_name='Country'),
        ),
        migrations.AlterField(
            model_name='guest',
            name='first_name',
            field=models.CharField(max_length=30, null=True, verbose_name='first name', blank=True),
        ),
        migrations.AlterField(
            model_name='guest',
            name='postal_code',
            field=models.PositiveIntegerField(null=True, verbose_name='postal code'),
        ),
    ]
