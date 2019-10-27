# -*- coding: utf-8 -*-
"""自定义 API 认证方式"""

import jwt
from django.conf import settings
from rest_framework import authentication, exceptions
from . import models


class BearerAuthentication(authentication.TokenAuthentication):
    """基于 JWT 的 Bearer 认证方式"""

    keyword = 'bearer'

    def authenticate_credentials(self, key):
        import time

        jwt_secret = getattr(settings, 'JWT_SECRET', getattr(settings, 'SECRET_KEY'))

        if not jwt_secret:
            raise exceptions.AuthenticationFailed(u'JWT_SECRET not setup')

        try:
            payload = jwt.decode(key, jwt_secret)

            now = int(time.time())
            is_auth = payload.get('exp_2fa', 0) > now

            try:
                user = models.User.objects.get(pk=payload.get('uid', 0))
                return user, is_auth or None
            except models.User.DoesNotExist:
                raise exceptions.AuthenticationFailed(u'User not exist')

        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed(u'Signature has expired')

        except jwt.DecodeError as err:
            raise exceptions.AuthenticationFailed(err)
