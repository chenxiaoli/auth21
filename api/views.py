# -*- coding: utf-8 -*-

import jwt
import time
import json
import logging
import datetime
import requests

import pyotp

from django.conf import settings

from rest_framework import exceptions, status, viewsets
from rest_framework import serializers as rest_serializers
from rest_framework.decorators import (
    api_view, authentication_classes, permission_classes)
from rest_framework.response import Response

from . import helpers
from . import models
from . import serializers
from .authentication import BearerAuthentication
from .permissions import IsUserAuthenticated

logger = logging.getLogger(__name__)


@api_view(['POST'])
def login(request):
    """用户登录"""

    # 若未设置 ``JWT_SECRET``，则使用 ``SECRET_KEY``
    jwt_secret = getattr(settings, 'JWT_SECRET', getattr(settings, 'SECRET_KEY'))
    jwt_expiration = getattr(settings, 'JWT_EXPIRATION', 3600)

    serializer = serializers.UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        print(serializer.data)
        user = models.User.objects.get(pk=serializer.data['uid'])
        user.last_login_time = datetime.datetime.now()
        user.save(update_fields=['last_login_time'])

        remote_ip = helpers.get_identify(request)
        params = [
            user.id, serializer.data['username'], remote_ip,
        ]
        logger.info(u'User login SUCCESS. '
                    u'(id={0}, login_name={1}, ip={2})'
                    u''.format(*params))

        now = int(time.time())
        exp = now + jwt_expiration

        payload = {'uid': user.pk, 'iat': now, 'exp': exp}
        if user.mobile:
            payload.update({"mobile":user.mobile})
        if user.nickname:
            payload.update({"nickname":user.nickname})
        if user.email:
            payload.update({"email":user.email})

        token = jwt.encode(payload, jwt_secret)

        return Response({'token': token})

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def test(request):
    return Response('Hello.')


@api_view(['GET'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def get_user_info(request):
    """返回用户基础信息"""
    user = request.user
    data = serializers.UserSimpleSerializer(user).data
    return Response(data)


@api_view(['POST'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def change_mobile(request):
    user = request.user
    serializer = serializers.UserChangeMobileSerializer(data=request.data)

    if serializer.is_valid():
        old_mobile = serializer.data['old_mobile']
        new_mobile = serializer.data['new_mobile']
        if old_mobile != user.mobile:
            raise rest_serializers.ValidationError({'old_mobile': ['手机号码与当前用户不匹配。']})
        user.mobile = new_mobile
        user.save(update_fields=['mobile'])
        return Response(dict(uid=user.id))

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def weixin_web_auth(request):
    """微信 Web 授权

    参考：https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140842

    :param request:
    :return:
    """
    import requests
    from django.db.models import Q
    from rest_framework.reverse import reverse

    login_url = '{0}://{1}{2}'.format(
        request.scheme,
        request.get_host(),
        str(reverse('{0}:login'.format(request.version))),
    )

    serializer = serializers.WeixinWebAuthSerializer(data=request.data)
    if serializer.is_valid():
        appid = getattr(settings, 'WEIXIN_APPID')
        appsecret = getattr(settings, 'WEIXIN_APPSECRET')
        code = serializer.data['code']
        url = 'https://api.weixin.qq.com/sns/oauth2/access_token'
        payload = {
            'appid': appid,
            'secret': appsecret,
            'code': code,
            'grant_type': 'authorization_code',
        }
        req = requests.get(url, params=payload)
        if req.status_code == 200:
            try:
                req_json = req.json()
                if 'openid' in req_json:
                    is_registered = False
                    output = dict()
                    _cond = Q(wx_openid=req_json.get('openid'))
                    output['openid'] = req_json.get('openid')
                    if 'unionid' in req_json:
                        _cond = _cond | Q(wx_openid=req_json.get('unionid'))
                        output['unionid'] = req_json.get('unionid')
                    if models.User.objects.filter(_cond).first():
                        is_registered = True
                    output['is_registered'] = is_registered
                    if is_registered:
                        # TODO
                        # 这里逻辑可能要变动下，``unionid`` /  ``openid`` 需求可能不一样
                        # 优先使用 ``unionid``
                        _username = req_json.get('unionid') or req_json.get('openid')
                        # 通过内部登录接口申请 token
                        _req = requests.post(
                            login_url,
                            json={'username': _username, 'password': 'weixin'},
                        )
                        if _req.status_code == 200:
                            try:
                                _req_json = _req.json()
                                output['token'] = _req_json.get('token')
                            except ValueError:
                                pass
                    return Response(output)
                if 'errcode' in req_json:
                    return Response(dict(errmsg=req_json.get('errmsg')), status=status.HTTP_200_OK)
            except ValueError:
                pass
        return Response(dict(errmsg=u'获取 access_token 失败'), status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view()
def weixin_authorize_url(request):
    """微信授权 URL"""

    import hashlib
    from urllib import parse
    callback_url = getattr(settings, 'WEIXIN_REDIRECT_URI', None) or ''
    appid = getattr(settings, 'WEIXIN_APPID', None) or ''

    auth_url = (
        'https://open.weixin.qq.com/connect/oauth2/authorize?'
        'appid={0}'
        '&redirect_uri={1}'
        '&response_type=code&scope={2}'
        '&state={3}'
        '#wechat_redirect'
    )

    state = hashlib.sha1(str(time.time()).encode('utf-8')).hexdigest()
    callback_url = parse.quote_plus(callback_url)
    _url = auth_url.format(appid, callback_url, 'snsapi_base', state)

    return Response(dict(url=_url))


@api_view(['POST'])
def weixin_access_token(request):
    """通过 code 获取 access_token"""

    appid = getattr(settings, 'WEIXIN_APPID', '')
    weixin = models.WeixinApp.objects.get(appid=appid)
    code = request.data.get('code') or ''
    url = 'https://api.weixin.qq.com/sns/oauth2/access_token'

    payload = {
        'appid': appid,
        'secret': weixin.appsecret,
        'code': code,
        'grant_type': 'authorization_code',
    }
    r = requests.get(url, params=payload)

    if r.status_code == status.HTTP_200_OK:
        output = dict()
        weixin_id_sort = models.UserWeixin.get_weixin_id_sort()
        try:
            _json = r.json()

            if 'errcode' in _json:
                return Response(dict(code=[_json.get('errmsg')]), status=status.HTTP_400_BAD_REQUEST)

            output['sort'] = weixin_id_sort

            if 'openid' in _json:
                output['openid'] = _json.get('openid')
            if 'unionid' in _json:
                output['unionid'] = _json.get('unionid')

            # 判断当前微信是否绑定
            if weixin_id_sort == models.UserWeixin.SORT_OPENID:
                wx_user = models.UserWeixin.get_instance(weixin_id_sort, _json.get('openid'))
            else:
                wx_user = models.UserWeixin.get_instance(weixin_id_sort, _json.get('unionid'))
            output['is_registered'] = wx_user is not None

            if wx_user:
                wx_user.token = _json.get('access_token')
                wx_user.expires_time = datetime.datetime.now() + \
                    datetime.timedelta(seconds=_json.get('expires_in', 7200) - 200)
                wx_user.save(update_fields=['token'])

            return Response(output)

        except json.JSONDecodeError:
            pass

    return Response(status=status.HTTP_502_BAD_GATEWAY)


@api_view(['POST'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def weixin_bind(request):
    """为已登录的用户绑定微信 OpenID"""
    user = request.user

    serializer = serializers.UserBindWeixinSerializer(data=request.data)
    if serializer.is_valid():

        if not hasattr(user, 'weixin'):
            sort = models.UserWeixin.get_weixin_id_sort()
            models.UserWeixin.objects.update_or_create(user=user, defaults=dict(sort=sort))

        if user.weixin.weixin_id != '' and len(user.weixin.weixin_id) >= 20:
            return Response(dict(weixin_id=[u'当前用户已绑定微信 OpenID。']),
                            status=status.HTTP_400_BAD_REQUEST)

        user.weixin.weixin_id = serializer.data['weixin_id']
        user.weixin.save(update_fields=['openid', 'unionid'])

        return Response(dict(uid=user.id))

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def weixin_config(request):
    """微信 JSSDK 配置"""
    serializer = serializers.WeixinConfigSerializer(data=request.data)
    if serializer.is_valid():
        appid = getattr(settings, 'WEIXIN_APPID', '')
        is_debug = getattr(settings, 'WEIXIN_JSSDK_DEBUG', False)
        weixin = models.WeixinApp.objects.get(appid=appid)
        url = serializer.data['url']
        print(url)
        sign = helpers.WeixinWebSign(weixin.jsapi_ticket, url)
        ret = sign.sign()
        context = {
            'appid': appid,
            'nonceStr': ret['nonceStr'],
            'timestamp': ret['timestamp'],
            'signature': ret['signature'],
            'debug': is_debug,
        }
        return Response(context)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def send_sms_code(request):
    """发送短信验证码"""
    from django.utils import timezone
    serializer = serializers.SendSMSCodeSerializer(data=request.data)
    if serializer.is_valid():
        mobile = serializer.data['mobile']
        context = serializer.data['context']
        remote_ip = helpers.get_identify(request)

        # 限制单个 IP 的请求频率
        _rate = getattr(settings, 'SMS_SEND_RATE', (300, 5))
        if not isinstance(_rate, (list, tuple)) or len(_rate) != 2:
            _rate = (300, 5)
        _begin_time = timezone.now() - datetime.timedelta(seconds=_rate[0])
        _codes = models.SMSCode.objects.filter(
            context=context, remote_ip=remote_ip, last_modified__gte=_begin_time)
        if _codes.count() >= _rate[1]:
            return Response(dict(detail=u'请求频率超过限制，请稍后再试。'),
                            status=status.HTTP_429_TOO_MANY_REQUESTS)

        old_sms_code = models.SMSCode.objects.filter(mobile=mobile, context=context).first()
        if old_sms_code and not old_sms_code.can_resend():
            return Response(dict(detail=u'该号码发送频率超过限制，请稍后再试。'),
                            status=status.HTTP_429_TOO_MANY_REQUESTS)

        code = models.SMSCode.gen_code(6)
        new_sms_code, created = models.SMSCode.objects.update_or_create(
            mobile=mobile, context=context, defaults=dict(code=code, remote_ip=remote_ip))

        sms_templates = getattr(settings, 'SMS_TEMPLATES', {})
        sms_sign = getattr(settings, 'SMS_SIGN', '')
        template = sms_templates.get(context, {})

        # 这里调用第三方短信接口发送短信验证码
        result = False

        _params = {'code': code}
        _params.update(template.get('template_params', {}))
        headers = {
            'Authorization': 'Bearer {0}'.format(getattr(settings, 'SMS_SERVICE_AUTH_TOKEN', '')),
        }
        data = {
            'mobiles': [mobile],
            'template_code': template.get('template_code', ''),
            'template_params': _params,
            'sign': template.get('sign', sms_sign),
        }

        sms_service_url = getattr(settings, 'SMS_SERVICE_URL')
        if not sms_service_url:
            return Response(dict(detail=u'短信服务配置异常。'), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            res = requests.post(sms_service_url, json=data, headers=headers)
            try:
                _json = res.json()
                result = _json.get('sent', False)
                return Response(dict(sent=result))
            except json.JSONDecodeError:
                pass
        except requests.exceptions.ConnectionError:
            pass
        return Response(status=status.HTTP_502_BAD_GATEWAY)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def check_sms_code(request):
    """检查短信验证码有效性"""
    serializer = serializers.CheckSMSCodeSerializer(data=request.data)

    if serializer.is_valid():
        mobile = serializer.data['mobile']
        code = serializer.data['code']
        context = serializer.data['context']
        result = models.SMSCode.check_code(mobile, code, context)
        return Response({'is_valid': result})

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def register_by_mobile(request):
    """用户通过手机注册"""
    serializer = serializers.UserRegisterByMobileSerializer(data=request.data)
    if serializer.is_valid():
        user = models.User(mobile=serializer.data['mobile'], password=serializer.data['password'])
        user.account_state = models.User.ACCOUNT_STATE_ACTIVATED
        user.save()

        return Response({'mobile': serializer.data['mobile'], 'uid': user.id})

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def register(request):
    """用户注册"""
    serializer = serializers.UserRegisterSerializer(data=request.data)
    if serializer.is_valid():
        data = serializer.data

        if data['typ'] == 1:
            # 邮箱注册
            kwargs = dict(email=data['username'], password=data['password'])
        elif data['typ'] == 2:
            # 手机号码注册
            kwargs = dict(mobile=data['username'], password=data['password'])
        else:
            # 用户名注册
            kwargs = dict(username=data['username'], password=data['password'])

        user = models.User(**kwargs)
        user.account_state = models.User.ACCOUNT_STATE_ACTIVATED
        user.save()

        return Response({'uid': user.id})

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def is_user_registered(request):
    """用户是否注册过"""
    serializer = serializers.IsUserRegisteredSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.data['username']
        type = serializer.data['type']
        is_user_existed = False
        if type == 'username':
            if models.User.check_username_existed(username):
                is_user_existed = True
        elif type == 'mobile':
            if models.User.check_mobile_existed(username):
                is_user_existed = True
        elif type == 'email':
            if models.User.check_email_existed(username):
                is_user_existed = True
        return Response({'is_user_registered': is_user_existed})
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def change_password(request):
    """已登录的用户修改密码"""
    user = request.user
    serializer = serializers.UserChangePasswordSerializer(data=request.data)
    if serializer.is_valid():
        if not user.check_password(serializer.data['old_password']):
            raise rest_serializers.ValidationError({'old_password': [u'旧密码不正确。']})
        user.password = serializer.data['new_password']
        user.save(update_fields=['password_hash'])
        return Response(dict(uid=user.id))
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def forget_password(request):
    """用户忘记密码"""
    serializer = serializers.UserForgetPasswordSerializer(data=request.data)
    if serializer.is_valid():
        mobile = serializer.data['mobile']
        user = models.User.objects.get(mobile=mobile)
        user.password = serializer.data['new_password']
        user.save(update_fields=['password_hash'])
        return Response(dict(uid=user.id))
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def check_2fa_password(request):
    """检查两步认证密码"""

    # 若未设置 ``JWT_SECRET``，则使用 ``SECRET_KEY``
    jwt_secret = getattr(settings, 'JWT_SECRET', getattr(settings, 'SECRET_KEY'))

    jwt_expiration = getattr(settings, 'JWT_EXPIRATION', 60 * 60)
    jwt_expiration_2fa = getattr(settings, 'JWT_EXPIRATION_2FA', 5 * 60)

    context = dict(request=request)
    serializer = serializers.UserCheck2FAPasswordSerializer(
        data=request.data, context=context)

    if serializer.is_valid():
        print(serializer.data)
        user = models.User.objects.get(pk=serializer.data['uid'])

        now = int(time.time())
        exp = now + jwt_expiration
        exp_2fa = now + jwt_expiration_2fa

        payload = {'uid': user.pk, 'iat': now, 'exp': exp, 'exp_2fa': exp_2fa}
        token = jwt.encode(payload, jwt_secret)

        return Response({'token': token})

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def test_2fa(request):
    """查询两步认证是否有效"""
    if not request.auth:
        raise exceptions.PermissionDenied
    return Response()


@api_view(['GET'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def otp(request):
    """两步认证信息"""

    user = request.user
    user_otp = models.UserOTP.get_user_otp(user)

    if user_otp.is_bind:
        return Response({})

    # 生成 密钥 和 URI
    issuer_name = getattr(settings, 'OTP_ISSUER_NAME', None) or 'auth21'
    user_pk = getattr(settings, 'USER_PRIMARY_KEY', None) or 'username'

    _otp = pyotp.TOTP(user_otp.secret)

    data = dict(
        secret=user_otp.secret,
        uri=_otp.provisioning_uri(
            str(getattr(user, user_pk, None) or user.id),
            issuer_name=issuer_name),
    )

    return Response(data)


@api_view(['POST'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def otp_open(request):
    """开启两步认证"""

    user = request.user
    user_otp = models.UserOTP.get_user_otp(user)

    if user_otp.is_bind:
        raise exceptions.PermissionDenied

    context = dict(request=request)
    serializer = serializers.UserOTPChangeSerializer(
        data=request.data, context=context)

    if serializer.is_valid():
        user_otp.bind_time = datetime.datetime.now()
        user_otp.save(update_fields=['bind_time'])
        return Response({})

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def otp_close(request):
    """关闭两步认证"""

    user = request.user
    user_otp = models.UserOTP.get_user_otp(user)

    if not user_otp.is_bind:
        raise exceptions.PermissionDenied

    context = dict(request=request)
    serializer = serializers.UserOTPChangeSerializer(
        data=request.data, context=context)

    if serializer.is_valid():
        user_otp.delete()
        return Response({})

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
