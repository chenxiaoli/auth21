# -*- coding: utf-8 -*-

from django.test import TestCase
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase, APIClient
from . import models


class UserAttributeTests(TestCase):
    def test_password_setter(self):
        """设置 password 之后, ``password_hash`` 不为空"""
        u = models.User(password='cat')
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        """获取 password 会触发 AttributeError 异常"""
        u = models.User(password='cat')
        with self.assertRaises(AttributeError):
            print(u.password)

    def test_password_verification(self):
        """测试密码验证功能"""
        u = models.User(password='cat')
        self.assertTrue(u.check_password('cat'))
        self.assertFalse(u.check_password('dog'))

    def test_password_salts_are_random(self):
        """测试密码盐是随机的"""
        u = models.User(password='cat')
        u2 = models.User(password='cat')
        self.assertTrue(u.password_hash != u2.password_hash)

    def test_password_hash(self):
        user = models.User()
        user.password = '123456'
        user.save()

        self.assertEqual(user.check_password('123456'), True)

        user.password_hash = '21fax.com'
        user.save()
        self.assertEqual(user.check_password('21fax.com'), True)


class MobilesTestCase(APITestCase):
    def test_mobiles(self):
        from .helpers import is_mobile
        # 测试有效的号段
        self.assertTrue(is_mobile('13000000000'))
        self.assertTrue(is_mobile('13100000000'))
        self.assertTrue(is_mobile('13200000000'))
        self.assertTrue(is_mobile('13300000000'))
        self.assertTrue(is_mobile('13400000000'))
        self.assertTrue(is_mobile('13490000000'))
        self.assertTrue(is_mobile('13500000000'))
        self.assertTrue(is_mobile('13600000000'))
        self.assertTrue(is_mobile('13700000000'))
        self.assertTrue(is_mobile('13800000000'))
        self.assertTrue(is_mobile('13900000000'))
        self.assertTrue(is_mobile('14500000000'))
        self.assertTrue(is_mobile('14700000000'))
        self.assertTrue(is_mobile('15000000000'))
        self.assertTrue(is_mobile('15100000000'))
        self.assertTrue(is_mobile('15200000000'))
        self.assertTrue(is_mobile('15300000000'))
        self.assertTrue(is_mobile('15500000000'))
        self.assertTrue(is_mobile('15600000000'))
        self.assertTrue(is_mobile('15700000000'))
        self.assertTrue(is_mobile('15800000000'))
        self.assertTrue(is_mobile('15900000000'))
        self.assertTrue(is_mobile('17000000000'))
        self.assertTrue(is_mobile('17050000000'))
        self.assertTrue(is_mobile('17090000000'))
        self.assertTrue(is_mobile('17600000000'))
        self.assertTrue(is_mobile('17700000000'))
        self.assertTrue(is_mobile('17800000000'))
        self.assertTrue(is_mobile('18000000000'))
        self.assertTrue(is_mobile('18100000000'))
        self.assertTrue(is_mobile('18200000000'))
        self.assertTrue(is_mobile('18300000000'))
        self.assertTrue(is_mobile('18400000000'))
        self.assertTrue(is_mobile('18500000000'))
        self.assertTrue(is_mobile('18600000000'))
        self.assertTrue(is_mobile('18700000000'))
        self.assertTrue(is_mobile('18800000000'))
        self.assertTrue(is_mobile('18900000000'))

        # 测试无效的号段
        self.assertFalse(is_mobile('14000000000'))
        self.assertFalse(is_mobile('14100000000'))
        self.assertFalse(is_mobile('14200000000'))
        self.assertFalse(is_mobile('14300000000'))
        self.assertFalse(is_mobile('14400000000'))
        self.assertFalse(is_mobile('14600000000'))
        self.assertFalse(is_mobile('14800000000'))
        self.assertFalse(is_mobile('14900000000'))
        self.assertFalse(is_mobile('15400000000'))
        self.assertFalse(is_mobile('17100000000'))
        self.assertFalse(is_mobile('17200000000'))
        self.assertFalse(is_mobile('17300000000'))
        self.assertFalse(is_mobile('17400000000'))
        self.assertFalse(is_mobile('17500000000'))
        self.assertFalse(is_mobile('17900000000'))

        # 测试手机号码位数
        self.assertTrue(is_mobile('13888888888'))
        self.assertFalse(is_mobile('138888888'))
        self.assertFalse(is_mobile('1388888888'))
        self.assertFalse(is_mobile('138888888888'))
        self.assertFalse(is_mobile('1388888888888'))


class UserLoginTests(APITestCase):

    def test_login_missing_fields(self):
        # 表单不完整
        response = self.client.post(reverse('v1:login'))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertContains(response, 'username', count=1, status_code=status.HTTP_400_BAD_REQUEST)
        self.assertContains(response, 'password', count=1, status_code=status.HTTP_400_BAD_REQUEST)

    def test_login_user_unactivated(self):
        _password = '21fax.com'
        user = models.User()
        user.username = '21fax'
        user.email = 'test@21fax.com'
        user.mobile = '13866668888'
        user.password = _password
        user.save()

        url = reverse('v1:login')

        # 用户名登录
        response = self.client.post(
            url, {'username': user.username, 'password': _password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 邮箱登录
        response = self.client.post(
            url, {'username': user.email, 'password': _password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # 手机登录
        response = self.client.post(
            url, {'username': user.mobile, 'password': _password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_via_username(self):
        _password = '21fax.com'
        user = models.User()
        user.account_state = user.ACCOUNT_STATE_ACTIVATED
        user.username = '21fax'
        user.email = 'test@21fax.com'
        user.mobile = '13866668888'
        user.password = _password
        user.save()

        url = reverse('v1:login')
        response = self.client.post(
            url, {'username': user.username, 'password': _password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    def test_login_via_email(self):
        _password = '21fax.com'
        user = models.User()
        user.account_state = user.ACCOUNT_STATE_ACTIVATED
        user.username = '21fax'
        user.email = 'test@21fax.com'
        user.mobile = '13866668888'
        user.password = _password
        user.save()

        url = reverse('v1:login')
        response = self.client.post(
            url, {'username': user.email, 'password': _password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    def test_login_via_mobile(self):
        _password = '21fax.com'
        user = models.User()
        user.account_state = user.ACCOUNT_STATE_ACTIVATED
        user.username = '21fax'
        user.email = 'test@21fax.com'
        user.mobile = '13866668888'
        user.password = _password
        user.save()

        url = reverse('v1:login')
        response = self.client.post(
            url, {'username': user.mobile, 'password': _password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    def test_login_via_mobile_and_code(self):
        _password = '21fax.com'
        user = models.User()
        user.account_state = user.ACCOUNT_STATE_ACTIVATED
        user.username = '21fax'
        user.email = 'test@21fax.com'
        user.mobile = '13866668888'
        user.password = _password
        user.save()

        sms_auth_token = '21fax.com'
        with self.settings(SMS_AUTH_TOKEN=sms_auth_token):
            _url = reverse('v1:send_sms_code')
            _res = self.client.post(
                _url,
                {'mobile': user.mobile, 'context': models.SMSCode.CONTEXT_LOGIN, 'token': sms_auth_token},
                format='json')
            self.assertEqual(_res.status_code, status.HTTP_200_OK)

            _code = models.SMSCode.objects.get(mobile=user.mobile, context=models.SMSCode.CONTEXT_LOGIN)

            url = reverse('v1:login')
            response = self.client.post(
                url, {'username': '13866668888', 'password': _code.code}, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('token', response.data)

    def test_login_via_weixin(self):
        _password = '21fax.com'
        user = models.User()
        user.account_state = user.ACCOUNT_STATE_ACTIVATED
        user.username = '21fax'
        user.email = 'test@21fax.com'
        user.mobile = '13866668888'
        user.password = _password
        user.wx_openid = 'okweifsodlweka2342oaiflid'
        user.save()

        url = reverse('v1:login')
        response = self.client.post(
            url, {'username': user.wx_openid, 'password': 'weixin'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
