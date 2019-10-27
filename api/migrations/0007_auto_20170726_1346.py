# -*- coding: utf-8 -*-
# Generated by Django 1.11.2 on 2017-07-26 13:46
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_auto_20170704_1346'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserGoogle',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('google_id', models.CharField(blank=True, max_length=128, verbose_name='谷歌 ID')),
                ('token', models.CharField(blank=True, max_length=256, verbose_name='Token')),
                ('expires_time', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'verbose_name': '谷歌账号',
                'verbose_name_plural': '谷歌账号',
            },
        ),
        migrations.CreateModel(
            name='UserWeixin',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sort', models.CharField(choices=[('openid', 'OpenID'), ('unionid', 'UnionID')], default='openid', max_length=16, verbose_name='ID 类型')),
                ('openid', models.CharField(blank=True, max_length=128, verbose_name='OpenID')),
                ('unionid', models.CharField(blank=True, max_length=128, verbose_name='UnionID')),
                ('token', models.CharField(blank=True, max_length=256, verbose_name='Token')),
                ('expires_time', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'verbose_name': '微信账号',
                'verbose_name_plural': '微信账号',
            },
        ),
        migrations.AlterField(
            model_name='user',
            name='email_confirmed',
            field=models.BooleanField(default=False, verbose_name='电子邮件是否验证'),
        ),
        migrations.AddField(
            model_name='userweixin',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='api.User', verbose_name='用户'),
        ),
        migrations.AddField(
            model_name='usergoogle',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='api.User', verbose_name='用户'),
        ),
    ]
