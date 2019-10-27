# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-04 13:46
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_auto_20170622_0936'),
    ]

    operations = [
        migrations.AlterField(
            model_name='smscode',
            name='context',
            field=models.CharField(choices=[('login', '登录'), ('register', '注册'), ('forget', '忘记'), ('transfer', '转移'), ('finance', '财务'), ('safety', '安全')], default='login', max_length=32, verbose_name='使用场景'),
        ),
    ]
