# -*- coding: utf-8 -*-

import datetime

import pyotp

from django.db import models
from django.contrib.auth.hashers import (
    check_password as _check_password, make_password, is_password_usable)
from django.utils import timezone


class User(models.Model):
    """用户"""

    ACCOUNT_STATE_FROZEN = -1      #: 冻结
    ACCOUNT_STATE_UNACTIVATED = 0  #: 未激活
    ACCOUNT_STATE_ACTIVATED = 1    #: 已激活

    ACCOUNT_STATES = (
        (ACCOUNT_STATE_FROZEN, u'冻结'),
        (ACCOUNT_STATE_UNACTIVATED, u'未激活'),
        (ACCOUNT_STATE_ACTIVATED, u'已激活'),
    )

    #: 用户名
    username = models.CharField(u'用户名', max_length=64, blank=True)

    #: 手机号码
    mobile = models.CharField(u'手机号码', max_length=16, blank=True)

    #: 电子邮箱
    email = models.CharField(u'电子邮箱', max_length=128, blank=True)

    #: 电子邮件是否验证
    email_confirmed = models.BooleanField(u'电子邮件是否验证', default=False)

    #: 微信 OpenID
    wx_openid = models.CharField(u'微信 OpenID', max_length=128, blank=True)

    #: 密码哈希值
    password_hash = models.CharField(max_length=128)

    #: 昵称
    nickname = models.CharField(u'昵称', max_length=64, blank=True)

    #: 注册时间
    register_time = models.DateTimeField(u'注册时间', auto_now_add=True)

    #: 最后登录时间
    last_login_time = models.DateTimeField(u'最后登录时间', null=True, blank=True)

    #: 账户状态
    account_state = models.SmallIntegerField(
        u'账户状态', default=ACCOUNT_STATE_UNACTIVATED, choices=ACCOUNT_STATES)

    class Meta:
        verbose_name = u'用户'
        verbose_name_plural = u'用户'

    def __unicode__(self):
        return self.pk

    def __str__(self):
        return str(self.pk)

    def check_password(self, password):
        """验证密码"""
        _hash = self.password_hash
        return _check_password(password, _hash)

    def save(self, *args, **kwargs):
        # 若 password_hash 不是加密密码的格式, 说明可能是明文密码,
        # 则把 password_hash 设置为密码
        if not is_password_usable(self.password_hash):
            self.password = self.password_hash
        super(User, self).save(*args, **kwargs)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = make_password(password)

    @staticmethod
    def check_mobile_existed(mobile):
        """检查手机是否已存在

        :param mobile: 手机号码
        """

        user = User.objects.filter(mobile=mobile).first()
        if user:
            return True
        return False

    @staticmethod
    def check_username_existed(username):
        """检查用户名是否已存在

        :param username: 用户名
        """

        user = User.objects.filter(username=username).first()
        if user:
            return True
        return False

    @staticmethod
    def check_email_existed(email):
        """检查用户名是否已存在

        :param email: 电子邮箱
        """

        user = User.objects.filter(email=email).first()
        if user:
            return True
        return False


class UserWeixin(models.Model):
    """微信账号"""

    SORT_OPENID = 'openid'
    SORT_UNIONID = 'unionid'
    SORTS = (
        (SORT_OPENID, u'OpenID'),
        (SORT_UNIONID, u'UnionID'),
    )

    #: 用户
    user = models.OneToOneField(User, verbose_name=u'用户', related_name='weixin')

    #: ID 类型
    sort = models.CharField(u'ID 类型', max_length=16, default=SORT_OPENID, choices=SORTS)

    #: 微信 OpenID
    openid = models.CharField(u'OpenID', max_length=128, blank=True)

    #: 微信 UnionID
    unionid = models.CharField(u'UnionID', max_length=128, blank=True)

    #: Token
    token = models.CharField(u'Token', max_length=256, blank=True)

    #: 过期时间
    expires_time = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = u'微信账号'
        verbose_name_plural = u'微信账号'

    def __str__(self):
        return str('{0}-{1}({2})'.format(self.user.id, self.weixin_id, self.sort))

    @property
    def weixin_id(self):
        if self.sort == self.SORT_OPENID:
            return self.openid
        else:
            return self.unionid

    @weixin_id.setter
    def weixin_id(self, weixin_id):
        if self.sort == self.SORT_OPENID:
            self.openid = weixin_id
        else:
            self.unionid = weixin_id

    @staticmethod
    def get_weixin_id_sort():
        """获取系统设置的微信 ID 类型"""
        from django.conf import settings
        _weixin_id_sort = getattr(settings, 'WEIXIN_ID_SORT', None) or UserWeixin.SORT_OPENID
        weixin_id_sort = UserWeixin.SORT_OPENID
        if _weixin_id_sort in [UserWeixin.SORT_OPENID, UserWeixin.SORT_UNIONID]:
            weixin_id_sort = _weixin_id_sort
        return weixin_id_sort

    @staticmethod
    def get_instance(sort, weixin_id):
        try:
            if sort == UserWeixin.SORT_OPENID:
                wx_user = UserWeixin.objects.get(sort=sort, openid=weixin_id)
            else:
                wx_user = UserWeixin.objects.get(sort=sort, unionid=weixin_id)
            return wx_user
        except UserWeixin.DoesNotExist:
            return None


class UserGoogle(models.Model):
    """谷歌账号"""

    #: 用户
    user = models.OneToOneField(User, verbose_name=u'用户', related_name='google')

    #: 谷歌 ID
    google_id = models.CharField(u'谷歌 ID', max_length=128, blank=True)

    #: Token
    token = models.CharField(u'Token', max_length=256, blank=True)

    #: 过期时间
    expires_time = models.DateTimeField(null=True, blank=True)  #: 过期时间

    class Meta:
        verbose_name = u'谷歌账号'
        verbose_name_plural = u'谷歌账号'

    def __str__(self):
        return str('{0}-{1}'.format(self.user.id, self.google_id))


class UserOTP(models.Model):
    """动态密码"""

    TYP_TOTP = 'totp'
    TYP_HOTP = 'hotp'
    TYPS = (
        (TYP_TOTP, u'TOTP'),
        (TYP_HOTP, u'HOTP'),
    )

    #: 用户
    user = models.OneToOneField(User, verbose_name=u'用户', related_name='otp')

    #: 类型
    typ = models.CharField(u'类型', max_length=16, default=TYP_TOTP, choices=TYPS)

    #: 密钥
    secret = models.CharField(u'密钥', max_length=128)

    #: 绑定时间
    bind_time = models.DateTimeField(u'绑定时间', null=True, blank=True)

    class Meta:
        verbose_name = u'动态密码'
        verbose_name_plural = u'动态密码'

    def __str__(self):
        return str('{0}-{1}({2})'.format(self.user.id, self.secret, self.typ))

    @property
    def is_bind(self):
        return isinstance(self.bind_time, datetime.datetime)

    @staticmethod
    def random_secret(length=32):
        return pyotp.random_base32(length=length)

    @staticmethod
    def get_user_otp(user):
        user_otp, created = UserOTP.objects.get_or_create(user=user)
        if created:
            user_otp.secret = UserOTP.random_secret()
            user_otp.save(update_fields=['secret'])
        return user_otp


class WeixinApp(models.Model):
    """微信公众号"""

    appid = models.CharField(max_length=64)
    appsecret = models.CharField(max_length=64, blank=True)
    name = models.CharField(max_length=128, blank=True)  #: 公众号名称
    access_token = models.CharField(max_length=256, blank=True)
    jsapi_ticket = models.CharField(max_length=256, blank=True)
    expires_time = models.DateTimeField(null=True, blank=True)  #: 过期时间

    class Meta:
        verbose_name = u'微信公众号'
        verbose_name_plural = u'微信公众号'

    def __str__(self):
        return str('%s[%s]' % (self.appid, self.name))

    def refresh_token(self):
        import requests
        token_url = 'https://api.weixin.qq.com/cgi-bin/token'
        ticket_url = 'https://api.weixin.qq.com/cgi-bin/ticket/getticket'
        token_payload = dict(
            grant_type='client_credential',
            appid=self.appid,
            secret=self.appsecret,
        )
        # 先获取 access_token
        req = requests.get(token_url, params=token_payload)
        if req.ok:
            ret = req.json()
            if 'access_token' in ret:
                self.access_token = ret['access_token']

                ticket_payload = dict(type='jsapi', access_token=self.access_token)
                # 再获取 jsapi ticket
                req = requests.get(ticket_url, params=ticket_payload)
                if req.ok:
                    ret = req.json()
                    if ret['errcode'] == 0 and 'ticket' in ret:
                        self.jsapi_ticket = ret['ticket']
                        self.expires_time = datetime.datetime.now() + \
                            datetime.timedelta(seconds=ret['expires_in'] - 200)
                        self.save()


class SMSCode(models.Model):
    """短信验证码"""

    CONTEXT_LOGIN = 'login'        #: 登录
    CONTEXT_REGISTER = 'register'  #: 注册
    CONTEXT_FORGET = 'forget'      #: 忘记
    CONTEXT_TRANSFER = 'transfer'  #: 转移/过户
    CONTEXT_SAFETY = 'safety'  #: 安全
    CONTEXT_FINANCE = 'finance'  #: 财务/资金

    CONTEXTS = (
        (CONTEXT_LOGIN, u'登录'),
        (CONTEXT_REGISTER, u'注册'),
        (CONTEXT_FORGET, u'忘记'),
        (CONTEXT_TRANSFER, u'转移'),
        (CONTEXT_FINANCE, u'财务'),
        (CONTEXT_SAFETY, u'安全'),
    )

    #: 手机号码
    mobile = models.CharField(u'手机号码', max_length=16)

    #: 验证码
    code = models.CharField(u'验证码', max_length=16)

    #: 使用场景
    context = models.CharField(u'使用场景', default=CONTEXT_LOGIN, choices=CONTEXTS, max_length=32)

    #: IP 地址
    remote_ip = models.CharField(u'IP 地址', max_length=32, blank=True)

    #: 最新修改时间
    last_modified = models.DateTimeField(u'最新修改时间', auto_now=True)

    class Meta:
        verbose_name = u'短信验证码'
        verbose_name_plural = u'短信验证码'

    def __unicode__(self):
        return u'<{0}-{1}>'.format(self.mobile, self.code)

    def __str__(self):
        return '{0}({1})@{2}'.format(self.mobile, self.code, self.context)

    def is_timeout(self, timeout=600):
        """判断验证码是否超时

        :param timeout: 超时时间, 单位为秒, 默认为600秒(10分钟)
        """

        now = timezone.now()
        return (self.last_modified > now) or (now - self.last_modified > datetime.timedelta(seconds=timeout))

    def can_resend(self, timeout=60):
        """是否可再次发送

        两次发送之间需要一定的时间间隔, 不能连续发送

        :param timeout: 超时时间, 单位为秒, 默认为60秒(1分钟)
        """

        now = timezone.now()
        return (self.last_modified < now) and (now - self.last_modified >= datetime.timedelta(seconds=timeout))

    @staticmethod
    def gen_code(length=4):
        """生成验证码"""
        if length < 4:
            raise Exception('Code Length must grater than 4.')
        import random
        return str(random.randrange(10 ** (length - 1), 10 ** length))

    @staticmethod
    def check_code(mobile, code, context):
        """检查验证码是否合法

        :param mobile: 手机号码
        :param code: 验证码
        :param context: 使用场景
        """

        sms_code = SMSCode.objects.filter(mobile=mobile, code=code, context=context).first()
        if sms_code and not sms_code.is_timeout():
            return True
        return False


def user_post_save(sender, instance, created, **kwargs):
    from django.conf import settings
    if created:
        _weixin_id_sort = getattr(settings, 'WEIXIN_ID_SORT', None) or UserWeixin.SORT_OPENID
        weixin_id_sort = UserWeixin.SORT_OPENID
        if _weixin_id_sort in [UserWeixin.SORT_OPENID, UserWeixin.SORT_UNIONID]:
            weixin_id_sort = _weixin_id_sort

        UserWeixin.objects.update_or_create(user=instance, defaults=dict(sort=weixin_id_sort))
        UserGoogle.objects.update_or_create(user=instance)


models.signals.post_save.connect(user_post_save, sender=User)
