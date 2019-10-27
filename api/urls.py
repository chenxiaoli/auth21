# -*- coding: utf-8 -*-

from django.conf.urls import include, url
from rest_framework import routers

from . import views

router = routers.DefaultRouter(trailing_slash=False)


urlpatterns = (
    url(r'^login$', views.login, name='login'),
    url(r'^test$', views.test, name='test'),
    url(r'^get-user-info$', views.get_user_info, name='get_user_info'),
    url(r'^change-mobile$', views.change_mobile, name='change_mobile'),
    url(r'^weixin-web-auth$', views.weixin_web_auth, name='weixin_web_auth'),
    url(r'^weixin-authorize-url$', views.weixin_authorize_url, name='weixin_authorize_url'),
    url(r'^weixin-access-token$', views.weixin_access_token, name='weixin_access_token'),
    url(r'^weixin-bind$', views.weixin_bind, name='weixin_bind'),
    url(r'^weixin-config$', views.weixin_config, name='weixin_config'),
    url(r'^send-sms-code$', views.send_sms_code, name='send_sms_code'),
    url(r'^check-sms-code$', views.check_sms_code, name='check_sms_code'),
    url(r'^register-by-mobile$', views.register_by_mobile, name='register_by_mobile'),
    url(r'^register$', views.register, name='register'),
    url(r'^is-user-registered$', views.is_user_registered, name='is_user_registered'),
    url(r'^change-password$', views.change_password, name='change_password'),
    url(r'^forget-password$', views.forget_password, name='forget_password'),
    url(r'^check-2fa-password$', views.check_2fa_password, name='check_2fa_password'),
    url(r'^test-2fa$', views.test_2fa, name='test_2fa'),
    url(r'^otp$', views.otp, name='otp'),
    url(r'^otp-open$', views.otp_open, name='otp_open'),
    url(r'^otp-close$', views.otp_close, name='otp_close'),
    url(r'^', include(router.urls)),
)
