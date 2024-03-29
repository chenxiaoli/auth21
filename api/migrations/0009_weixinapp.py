# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-26 14:39
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_auto_20170726_1402'),
    ]

    operations = [
        migrations.CreateModel(
            name='WeixinApp',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('appid', models.CharField(max_length=64)),
                ('appsecret', models.CharField(blank=True, max_length=64)),
                ('name', models.CharField(blank=True, max_length=128)),
                ('access_token', models.CharField(blank=True, max_length=256)),
                ('jsapi_ticket', models.CharField(blank=True, max_length=256)),
                ('expires_time', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'verbose_name': '微信公众号',
                'verbose_name_plural': '微信公众号',
            },
        ),
    ]
