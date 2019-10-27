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
((170[059])\d{7})
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
