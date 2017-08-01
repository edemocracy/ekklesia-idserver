# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='invitation',
            name='status',
            field=models.PositiveIntegerField(default=1, verbose_name='user type', choices=[(0, b'deleted'), (1, b'new'), (4, b'registering'), (2, b'registered'), (3, b'failed'), (5, b'verify'), (6, b'verified'), (7, b'reset')]),
        ),
    ]
