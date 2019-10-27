# -*- coding: utf-8 -*-

from rest_framework import throttling


class CommonRateThrottle(throttling.SimpleRateThrottle):

    scope = 'common'

    def get_cache_key(self, request, view):
        return self.cache_format % {
            'scope': self.scope,
            'ident': self.get_ident(request)
        }


class SmsCodePerMinuteThrottle(CommonRateThrottle):
    scope = 'sms_code_per_minute'


class SmsCodePerHourThrottle(CommonRateThrottle):
    scope = 'sms_code_per_hour'
