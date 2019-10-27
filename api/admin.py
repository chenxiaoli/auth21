# -*- coding: utf-8 -*-

from django.contrib import admin

from . import models


class UserWeixinInlineAdmin(admin.TabularInline):
    model = models.UserWeixin


class UserGoogleInlineAdmin(admin.TabularInline):
    model = models.UserGoogle


class UserOTPInlineAdmin(admin.TabularInline):
    model = models.UserOTP


class UserAdmin(admin.ModelAdmin):
    list_display = [
        'pk', 'mobile', 'username', 'email',
        'register_time', 'account_state',
    ]
    search_fields = ['mobile', 'username', 'email']
    list_filter = ['account_state']
    inlines = [UserWeixinInlineAdmin, UserGoogleInlineAdmin, UserOTPInlineAdmin]


class WeixinAppAdmin(admin.ModelAdmin):
    list_display = ['id', 'appid', 'name']
    search_fields = ['appid', 'name']


class SMSCodeAdmin(admin.ModelAdmin):
    list_display = [
        'pk', 'mobile', 'code', 'context', 'last_modified',
        'is_timeout',
    ]
    search_fields = ['mobile']
    list_filter = ['context']

    def is_timeout(self, obj):
        return obj.is_timeout()
    is_timeout.short_description = u'是否超时'


admin.site.register(models.User, UserAdmin)
admin.site.register(models.WeixinApp, WeixinAppAdmin)
admin.site.register(models.SMSCode, SMSCodeAdmin)
