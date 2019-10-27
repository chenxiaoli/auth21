# -*- coding: utf-8 -*-

import re
import time
import string
import random
import hashlib

# 手机号码正则
_re_str = r'''^(
(((13[0-9])|(14[57])|(15[^4])|(17[6-8])|(18[0-9]))\d{8})
|
((17[0-9])\d{8})
)$
'''
_is_mobile_re = re.compile(_re_str, re.VERBOSE)


def is_mobile(mobile):
    """检测是否为手机号码

    :param mobile: 手机号码
    """
    if _is_mobile_re.match(mobile):
        return True
    return False


def get_identify(request):
    """获取请求方的 IP 地址"""
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    remote_addr = request.META.get('REMOTE_ADDR')
    return ''.join(xff.split()) if xff else remote_addr


def md5_b16(text):
    """计算 MD5 值, 并取中间 16 位"""
    from hashlib import md5

    if isinstance(text, str):
        text = text.encode('utf-8')

    digest = md5(text).hexdigest()[8:24]

    return digest.lower()


def is_email(email):
    """检测是否是 EMAIL 地址"""
    from django.core import validators

    try:
        validators.EmailValidator()(email)
        return True
    except validators.ValidationError:
        return False


def update_url_params(url, params=None):
    """扩展 URL 查询参数"""

    from urllib import parse

    url = url or '/'
    if not params:
        params = dict()

    bits = list(parse.urlparse(url))
    qs = parse.parse_qs(bits[4])
    qs.update(params)
    bits[4] = parse.urlencode(qs, True)

    return parse.urlunparse(bits)


class WeixinWebSign(object):
    """微信 JSSDK 签名"""

    def __init__(self, jsapi_ticket, url):
        self.ret = {
            'nonceStr': self._create_nonce_str(),
            'jsapi_ticket': jsapi_ticket,
            'timestamp': self._create_timestamp(),
            'url': url
        }

    @staticmethod
    def _create_nonce_str():
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(15))

    @staticmethod
    def _create_timestamp():
        return int(time.time())

    def sign(self):
        sign_string = '&'.join(['%s=%s' % (key.lower(), self.ret[key]) for key in sorted(self.ret)])
        self.ret['signature'] = hashlib.sha1(sign_string.encode('utf-8')).hexdigest()
        return self.ret


def send_email(to, subject, template, context=None):
    """发送电子邮件

    :param to: 收件人
    :param subject: 主题
    :param template: 模板名称, 不带后缀, 默认取 txt 和 html 两个后缀的模板
    :param context: 模板变量
    """

    from django.conf import settings
    from django.core.mail import EmailMultiAlternatives
    from django.template import Engine, Context

    engine = Engine.get_default()

    if context is None:
        context = dict()

    sitename = getattr(settings, 'OTP_ISSUER_NAME', None) or ''

    subject = '{0} - {1}'.format(sitename, subject)
    email_host_user = getattr(settings, 'EMAIL_HOST_USER', None) or 'no-reply@example.com'
    from_email = '{0} <{1}>'.format(sitename, email_host_user)

    context = Context(context)
    tpl_text = engine.get_template('{0}.txt'.format(template))
    tpl_html = engine.get_template('{0}.html'.format(template))
    text_content = tpl_text.render(context)
    html_content = tpl_html.render(context)

    msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
    msg.attach_alternative(html_content, 'text/html')

    count = msg.send(fail_silently=True)

    return count == 1


def get_weixin_userinfo(openid):
    """根据 openid 获取微信用户信息"""

    import json
    import requests
    from django.conf import settings
    from . import models

    appid = getattr(settings, 'WEIXIN_APPID', '')

    weixin = models.WeixinApp.objects.get(appid=appid)

    url = 'https://api.weixin.qq.com/cgi-bin/user/info'

    payload = {
        'access_token': weixin.access_token,
        'openid': openid,
        'lang': 'zh_CN',
    }
    r = requests.get(url, params=payload)

    output = dict()

    if r.status_code == 200:

        try:
            _json = r.json()

            if 'openid' in _json:
                output = _json

        except json.JSONDecodeError:
            pass

    return output


def feedback_profile(user_id):
    """回传个人信息(系统级的)"""

    import requests
    from django.conf import settings
    from . import models

    auth_server_host = getattr(settings, 'API_SERVER_HOST', '')
    user = models.User.objects.get(id=user_id)

    payload = {
        "nickname": user.nickname,
        "mobile": user.mobile,
        "weixin": {
            "openid": user.weixin.openid,
            "unionid": user.weixin.unionid,
        }
    }

    _token, _ = make_user_token(user.id, expiration=2 * 60)
    headers = {
        'Authorization': 'Bearer ' + _token.decode(),
    }

    url = '{0}{1}'.format(auth_server_host, '/api/v1/frontend/agents/profile2')

    res = requests.post(url, json=payload, headers=headers)
    if res.status_code == 200:
        print('success')


def make_user_token(uid, params=None, expiration=None):
    """生成用户登录 Token"""
    import jwt
    from django.conf import settings

    if params is None:
        params = dict()

    # 若未设置 ``JWT_SECRET``，则使用 ``SECRET_KEY``
    jwt_secret = getattr(settings, 'JWT_SECRET', None) or getattr(settings, 'SECRET_KEY', '')
    jwt_expiration = expiration or getattr(settings, 'JWT_EXPIRATION', None) or 3600

    now = int(time.time())
    exp = now + jwt_expiration

    payload = {'uid': uid, 'iat': now, 'exp': exp}
    payload.update(params)

    token = jwt.encode(payload, jwt_secret)

    return token, jwt_expiration
