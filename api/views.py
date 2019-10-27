# -*- coding: utf-8 -*-

import jwt
import time
import json
import logging
import datetime
import requests

import pyotp

from django.conf import settings
from django.db import transaction

from rest_framework import exceptions, status, viewsets
from rest_framework import serializers as rest_serializers
from rest_framework.decorators import (
    list_route,
    api_view, authentication_classes, permission_classes)
from rest_framework.response import Response

from . import helpers
from . import models
from . import serializers
from . import throttling
from .authentication import BearerAuthentication
from .permissions import IsUserAuthenticated

logger = logging.getLogger(__name__)


@api_view(['POST'])
def login(request):
    """用户登录"""

    serializer = serializers.UserLoginSerializer(data=request.data)
    if serializer.is_valid():
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

        token, jwt_expiration = helpers.make_user_token(user.pk)

        res = Response({'token': token})
        res.set_cookie('token', token, max_age=jwt_expiration - 120,
                       httponly=settings.SESSION_COOKIE_HTTPONLY or None)

        return res

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def logout(request):
    """注销登录"""
    res = Response()
    res.delete_cookie('token')
    return res


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

    from urllib import parse
    from django.core.signing import TimestampSigner

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

    signer = TimestampSigner()
    state = signer.sign('biz')
    callback_url = parse.quote_plus(callback_url)
    scope = getattr(settings, 'WEIXIN_SCOPE', None) or 'snsapi_base'
    _url = auth_url.format(appid, callback_url, scope, state)

    return Response(dict(url=_url))


@api_view()
def weixin_qrconnect_url(request):
    """微信扫码登录 URL"""

    from urllib import parse
    from django.core.signing import TimestampSigner

    callback_url = getattr(settings, 'WEIXIN_WEB_REDIRECT_URI', None) or ''
    appid = getattr(settings, 'WEIXIN_WEB_APPID', None) or ''

    auth_url = (
        'https://open.weixin.qq.com/connect/qrconnect?'
        'appid={0}'
        '&redirect_uri={1}'
        '&response_type=code&scope={2}'
        '&state={3}'
        '#wechat_redirect'
    )

    signer = TimestampSigner()
    state = signer.sign('web')
    callback_url = parse.quote_plus(callback_url)
    scope = 'snsapi_login'
    _url = auth_url.format(appid, callback_url, scope, state)

    return Response(dict(url=_url))


@api_view(['POST'])
def weixin_access_token(request):
    """通过 code 获取 access_token"""

    from urllib import parse
    from django.core.signing import TimestampSigner, SignatureExpired, BadSignature

    appid = getattr(settings, 'WEIXIN_APPID', '')
    code = request.data.get('code') or ''
    state = parse.unquote_plus(request.data.get('state') or '')

    signer = TimestampSigner()
    try:
        # 5 分钟有效, 因为 code 也是这个有效期
        state = signer.unsign(state, max_age=5 * 60)
        if state == 'web':
            appid = getattr(settings, 'WEIXIN_WEB_APPID', '')
    except (SignatureExpired, BadSignature):
        return Response(dict(state=['state 无效']), status=status.HTTP_400_BAD_REQUEST)

    weixin = models.WeixinApp.objects.get(appid=appid)
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

            if 'unionid' in _json:
                wx_account, _ = models.WeixinAccount.objects.get_or_create(
                    sort=state, unionid=_json.get('unionid'))
            else:
                wx_account, _ = models.WeixinAccount.objects.get_or_create(
                    sort=state, openid=_json.get('openid'))

            output['sort'] = weixin_id_sort

            if 'openid' in _json:
                output['openid'] = _json.get('openid')
                wx_account.openid = _json.get('openid')
            if 'unionid' in _json:
                output['unionid'] = _json.get('unionid')
                wx_account.unionid = _json.get('unionid')

            wx_account.access_token = _json.get('access_token')
            wx_account.save(update_fields=['openid', 'unionid', 'access_token'])

            # 判断当前微信是否绑定
            if weixin_id_sort == models.UserWeixin.SORT_OPENID:
                wx_user = models.UserWeixin.get_instance(weixin_id_sort, _json.get('openid'))
            else:
                wx_user = models.UserWeixin.get_instance(weixin_id_sort, _json.get('unionid'))
            output['is_registered'] = wx_user is not None

            jwt_expiration = None
            if wx_user:
                _token, jwt_expiration = helpers.make_user_token(wx_user.user.id, expiration=7 * 24 * 3600)
                output['token'] = _token

                if state == 'biz' and not wx_user.openid and output['openid']:
                    wx_user.openid = output['openid']

                wx_user.token = _json.get('access_token')
                wx_user.refresh_token = _json.get('refresh_token')
                wx_user.expires_time = datetime.datetime.now() + \
                    datetime.timedelta(seconds=_json.get('expires_in', 7200) - 200)
                wx_user.save(update_fields=['openid', 'token', 'refresh_token', 'expires_time'])

                if state == 'biz':
                    try:
                        helpers.feedback_profile(wx_user.user.id)
                    except:
                        pass

            res = Response(output)
            if jwt_expiration and 'token' in output:
                res.set_cookie('token', output['token'], max_age=jwt_expiration - 120,
                               httponly=settings.SESSION_COOKIE_HTTPONLY or None)

            return res

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

        sort = models.UserWeixin.get_weixin_id_sort()
        if not hasattr(user, 'weixin'):
            models.UserWeixin.objects.update_or_create(user=user, defaults=dict(sort=sort))

        if user.weixin.weixin_id != '' and len(user.weixin.weixin_id) >= 20:
            return Response(dict(weixin_id=[u'当前用户已绑定微信 OpenID。']),
                            status=status.HTTP_400_BAD_REQUEST)

        weixin_id = serializer.data['weixin_id']

        # 针对微信公众号, 要把 openid 传到业务服务器
        sort_biz = models.WeixinApp.SORT_BIZ
        if sort == models.UserWeixin.SORT_UNIONID:
            wx_account = models.WeixinAccount.objects.filter(
                sort=sort_biz, unionid=weixin_id).first()
        else:
            wx_account = models.WeixinAccount.objects.filter(
                sort=sort_biz, openid=weixin_id).first()

        with transaction.atomic():
            user.weixin.weixin_id = serializer.data['weixin_id']

            if wx_account:
                user.weixin.openid = wx_account.openid

            user.weixin.save(update_fields=['openid', 'unionid'])

            if wx_account:
                helpers.feedback_profile(user.id)

            return Response(dict(uid=user.id))

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def weixin_config(request):
    """微信 JSSDK 配置"""
    serializer = serializers.WeixinConfigSerializer(data=request.data)
    if serializer.is_valid():
        appid = getattr(settings, 'WEIXIN_APPID', '')
        is_debug = getattr(settings, 'WEIXIN_JSSDK_DEBUG', False)
        weixin = models.WeixinApp.objects.get(sort=models.WeixinApp.SORT_BIZ, appid=appid)
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
    from django.core.mail import EmailMultiAlternatives
    from django.template import engines

    serializer = serializers.SendSMSCodeSerializer(data=request.data)
    if serializer.is_valid():
        _is_email = False

        mobile = _email = serializer.data['mobile']
        context = serializer.data['context']
        remote_ip = helpers.get_identify(request)

        if helpers.is_email(mobile):
            _is_email = True
            mobile = helpers.md5_b16(mobile)

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
            return Response(dict(detail=u'发送频率超过限制，请稍后再试。'),
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

        # 发送邮件验证码
        if _is_email:
            django_engine = engines['django']
            contexts = dict(models.SMSCode.CONTEXTS)
            _params['context'] = contexts.get(context) or ''

            sign = template.get('sign') or sms_sign
            subject = '{0} - {1}'.format(sign, '验证码')
            email_host_user = getattr(settings, 'EMAIL_HOST_USER', None) or 'no-reply@example.com'
            from_email = '{0} <{1}>'.format(sign, email_host_user)
            to = _email

            tpl_string = template.get('email_template') or '验证码: {{ code }}'
            tpl = django_engine.from_string(tpl_string)
            text_content = tpl.render(_params)
            html_content = text_content
            msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
            msg.attach_alternative(html_content, 'text/html')
            count = msg.send(fail_silently=True)

            send = count == 1
            return Response(dict(send=send, type='email'))

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
                return Response(dict(sent=result, type='sms'))
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
        if helpers.is_email(mobile):
            mobile = helpers.md5_b16(mobile)
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
        payload = dict()
        mobile = serializer.data['mobile']
        password = serializer.data['password']
        nickname= serializer.data['nickname']

        payload['nickname'] =nickname
        if helpers.is_email(mobile):
            user = models.User(email=mobile, password=password)
            user.email_confirmed = True
            payload['mobile'] = ''
            payload['email'] = mobile
        else:
            user = models.User(mobile=mobile, password=password)
            payload['mobile'] = mobile
            payload['email'] = ''
        user.nickname=nickname
        user.account_state = models.User.ACCOUNT_STATE_ACTIVATED
        user.save()

        payload['uid'] = user.id


        return Response(payload)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def register(request):
    """用户注册"""
    serializer = serializers.UserRegisterSerializer(data=request.data)
    if serializer.is_valid():
        data = serializer.data

        username = data['username']
        password = data['password']

        if data['typ'] == 1:
            # 邮箱注册
            kwargs = dict(email=username, password=password)
        elif data['typ'] == 2:
            # 手机号码注册
            kwargs = dict(mobile=username, password=password)
        else:
            # 用户名注册
            kwargs = dict(username=username, password=password)

        user = models.User(**kwargs)
        user.account_state = models.User.ACCOUNT_STATE_ACTIVATED
        user.save()

        output = dict(uid=user.id)
        if data['typ'] == 3:
            # 通过微信 openid 注册, 则同时绑定微信信息
            user.password_hash = ''
            user.save(update_fields=['password_hash'])
            sort = models.UserWeixin.get_weixin_id_sort()
            info = helpers.get_weixin_userinfo(username)
            if 'openid' in info:
                defaults = dict(openid=info.get('openid'))
                if sort == models.UserWeixin.SORT_OPENID:
                    models.UserWeixin.objects.update_or_create(user=user, sort=sort, defaults=defaults)
                else:
                    unionid = info.get('unionid')
                    if unionid:
                        defaults['unionid'] = unionid
                    models.UserWeixin.objects.update_or_create(user=user, sort=sort, defaults=defaults)
                output['weixin'] = info

        return Response(output)

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
        elif type == 'weixin':
            sort = models.UserWeixin.get_weixin_id_sort()
            info = helpers.get_weixin_userinfo(username)
            if 'openid' in info:
                if sort == models.UserWeixin.SORT_OPENID:
                    is_user_existed = models.UserWeixin.is_exists(sort, info.get('openid'))
                else:
                    is_user_existed = models.UserWeixin.is_exists(sort, info.get('unionid'))
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
        if helpers.is_email(mobile):
            user = models.User.objects.get(email=mobile)
        else:
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

    jwt_expiration_2fa = getattr(settings, 'JWT_EXPIRATION_2FA', 5 * 60)

    context = dict(request=request)
    serializer = serializers.UserCheck2FAPasswordSerializer(
        data=request.data, context=context)

    if serializer.is_valid():
        user = models.User.objects.get(pk=serializer.data['uid'])

        now = int(time.time())
        exp_2fa = now + jwt_expiration_2fa

        params = {'exp_2fa': exp_2fa}
        token, jwt_expiration = helpers.make_user_token(user.pk, params=params)

        res = Response({'token': token})
        res.set_cookie('token', token, max_age=jwt_expiration - 120,
                       httponly=settings.SESSION_COOKIE_HTTPONLY or None)

        return res

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


class UserViewSet(viewsets.ViewSet):

    throttle_scope = None
    throttle_actions = [
        'resend_confirmation_email', 'confirm_email',
    ]

    def get_throttles(self):
        if self.action in self.throttle_actions:
            self.throttle_scope = 'user.' + self.action
        return super().get_throttles()

    @list_route(methods=['POST'], url_path='resend-confirmation-email')
    def resend_confirmation_email(self, request):
        """重发确认邮件"""

        from django.core import signing

        serializer = serializers.EmailResendConfirmationSerializer(data=request.data)

        if serializer.is_valid():
            to = serializer.data['email']

            sitename = getattr(settings, 'SMS_SIGN', None) or \
                getattr(settings, 'OTP_ISSUER_NAME', None) or 'Auth21'
            email_confirm_exp = getattr(settings, 'EMAIL_CONFIRM_EXPIRATION', None) or 3600
            email_confirm_url = getattr(settings, 'EMAIL_CONFIRM_URL', None) or '/'

            token = signing.dumps({"email": to})
            link = helpers.update_url_params(email_confirm_url, dict(token=token))

            context = dict(
                hour=int(email_confirm_exp / 3600),
                link=link,
                sitename=sitename,
            )

            send = helpers.send_email(to, '注册邮箱确认', 'api/email/confirm', context=context)

            return Response(dict(send=send))

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @list_route(methods=['POST'], url_path='confirm-email')
    def confirm_email(self, request):
        """邮件确认"""

        from django.core import signing

        serializer = serializers.EmailResendConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = signing.loads(serializer.data['token'])

            user = models.User.objects.get(email=token['email'])
            if not user.email_confirmed:
                user.email_confirmed = True
                user.save(update_fields=['email_confirmed'])

            return Response(dict(confirmed=True))

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class WeixinViewSet(viewsets.ViewSet):
    """微信公众号接口"""

    @list_route(methods=['POST'], url_path='send-custom-message')
    def send_custom_message(self, request):
        """发送客服消息"""
        appid = getattr(settings, 'WEIXIN_APPID', '')
        wx = models.WeixinApp.objects.get(appid=appid)

        _url = 'https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={0}'
        url = _url.format(wx.access_token)

        data = request.data.copy()

        parent_uid = data.pop('parent_uid', None)
        try:
            parent_user = models.User.objects.get(id=parent_uid)
            data['touser'] = parent_user.weixin.openid
        except models.User.DoesNotExist:
            pass

        try:
            assert 'touser' in data

            # 不转成 UTF-8 的话, 在会话窗口显示 Unicode 编码
            raw = (json.dumps(data, ensure_ascii=False)).encode()

            res = requests.post(url, data=raw)
            if res.status_code == status.HTTP_200_OK:
                _json = res.json()
                if _json.get('errcode') == 0:
                    return Response(_json)
                else:
                    return Response(_json, status=status.HTTP_400_BAD_REQUEST)
        except (requests.exceptions.ConnectionError, AssertionError):
            return Response(status=status.HTTP_502_BAD_GATEWAY)

    @list_route(methods=['POST'], url_path='send-template-message')
    def send_template_message(self, request):
        """发送模板消息"""
        appid = getattr(settings, 'WEIXIN_APPID', '')
        wx = models.WeixinApp.objects.get(appid=appid)

        _url = 'https://api.weixin.qq.com/cgi-bin/message/template/send?access_token={0}'
        url = _url.format(wx.access_token)

        data = request.data.copy()

        parent_uid = data.pop('parent_uid', None)
        try:
            parent_user = models.User.objects.get(id=parent_uid)
            data['touser'] = parent_user.weixin.openid
        except models.User.DoesNotExist:
            pass

        try:
            assert 'touser' in data

            res = requests.post(url, json=data)
            if res.status_code == status.HTTP_200_OK:
                _json = res.json()
                if _json.get('errcode') == 0:
                    return Response(_json)
                else:
                    return Response(_json, status=status.HTTP_400_BAD_REQUEST)
        except (requests.exceptions.ConnectionError, AssertionError):
            return Response(status=status.HTTP_502_BAD_GATEWAY)

    @list_route(methods=['POST'], url_path='create-qrcode')
    def create_qrcode(self, request):
        """创建推广二维码"""
        appid = getattr(settings, 'WEIXIN_APPID', '')
        wx = models.WeixinApp.objects.get(appid=appid)

        _url = 'https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token={0}'
        url = _url.format(wx.access_token)

        data = request.data.copy()

        try:
            # 不转成 UTF-8 的话, 在会话窗口显示 Unicode 编码
            raw = (json.dumps(data, ensure_ascii=False)).encode()

            res = requests.post(url, data=raw)
            if res.status_code == status.HTTP_200_OK:
                _json = res.json()
                if 'ticket' in _json:
                    return Response(_json)
                else:
                    return Response(_json, status=status.HTTP_400_BAD_REQUEST)
        except requests.exceptions.ConnectionError:
            return Response(status=status.HTTP_502_BAD_GATEWAY)

    @list_route(methods=['POST'], url_path='upload-media')
    def upload_media(self, request):
        """上传多媒体文件"""
        appid = getattr(settings, 'WEIXIN_APPID', '')
        wx = models.WeixinApp.objects.get(appid=appid)

        data = request.data.copy()
        media_type = data.get('type', 'image')

        _url = 'https://api.weixin.qq.com/cgi-bin/media/upload?access_token={0}&type={1}'
        url = _url.format(wx.access_token, media_type)

        try:
            res = requests.post(url, files=dict(media=data.get('media')))
            if res.status_code == status.HTTP_200_OK:
                _json = res.json()
                if 'media_id' in _json:
                    return Response(_json)
                else:
                    return Response(_json, status=status.HTTP_400_BAD_REQUEST)
        except requests.exceptions.ConnectionError:
            return Response(status=status.HTTP_502_BAD_GATEWAY)


@api_view(['PUT'])
@authentication_classes([BearerAuthentication])
@permission_classes([IsUserAuthenticated])
def edit_user_info(request):
    user = request.user
    serializer = serializers.UserInfoSerializer(user,data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
