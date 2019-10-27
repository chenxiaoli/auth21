# -*- coding: utf-8 -*-

from django.conf import settings
from rest_framework import serializers
from . import models
from . import helpers


class UserSimpleSerializer(serializers.ModelSerializer):
    """用户模型简易序列化器"""
    uid = serializers.SerializerMethodField()

    class Meta:
        model = models.User
        fields = ('id', 'uid', 'mobile','nickname',"email", 'username','wx_openid')

    def get_uid(self, obj):
        return obj.pk


class UserLoginSerializer(serializers.Serializer):
    """用户登录序列化器"""
    username = serializers.CharField(
        max_length=64, error_messages={'required': u'登录名不能为空'})
    password = serializers.CharField(
        max_length=64, error_messages={'required': u'密码不能为空'})
    uid = serializers.IntegerField(default=0)

    def validate_username(self, value):
        """检查登录名

        :param value:
        """
        # 若登录名为邮箱, 则没有确认之前不允许登录
        if helpers.is_email(value):
            user = models.User.objects.filter(email=value).first()
            if user and not user.email_confirmed:
                raise serializers.ValidationError(u'email 地址未确认')

        return value

    def validate_password(self, value):
        """检查密码

        :param value:
        """
        if len(value) < 6:
            raise serializers.ValidationError(u'密码太短')
        return value

    def validate(self, data):
        from django.core import validators
        from .helpers import is_mobile
        username = data['username']
        password = data['password']
        user = None
        is_mobile_login = False
        is_code_login = False

        def _check_is_activated(_user):
            """检查用户是否可登录"""
            if _user.account_state != models.User.ACCOUNT_STATE_ACTIVATED:
                raise serializers.ValidationError(u'当前账号不可用')

        if password.upper() == 'WEIXIN' and len(username) >= 20:
            weixin_id_sort = models.UserWeixin.get_weixin_id_sort()

            try:
                if weixin_id_sort == models.UserWeixin.SORT_OPENID:
                    wx_user = models.UserWeixin.objects.get(openid=username, sort=weixin_id_sort)
                else:
                    wx_user = models.UserWeixin.objects.get(unionid=username, sort=weixin_id_sort)
                user = wx_user.user
                _check_is_activated(user)
                data['uid'] = user.pk  # 将 uid 传到视图函数中使用
                return data
            except models.UserWeixin.DoesNotExist:
                pass

        if is_mobile(username):
            try:
                user = models.User.objects.get(mobile=username)
                is_mobile_login = True
            except models.User.DoesNotExist:
                pass

        try:
            validators.EmailValidator()(username)
            try:
                user = models.User.objects.get(email=username)
            except models.User.DoesNotExist:
                pass
        except validators.ValidationError:
            pass

        if not user:
            try:
                user = models.User.objects.get(username=username)
            except models.User.DoesNotExist:
                pass

        if user:
            _check_is_activated(user)

            if is_mobile_login:
                is_code_login = models.SMSCode.check_code(
                    mobile=username, code=password, context=models.SMSCode.CONTEXT_LOGIN)

            # 检验密码或者短信验证码
            if user.check_password(password) or is_code_login:
                data['uid'] = user.pk  # 将 uid 传到视图函数中使用
                return data

        raise serializers.ValidationError(u'登录名或密码错误')


class UserCheck2FAPasswordSerializer(serializers.Serializer):
    """检查两步认证密码列化器"""

    password = serializers.CharField(
        max_length=32, error_messages={'required': u'密码不能为空'})

    uid = serializers.IntegerField(default=0)

    def validate_password(self, value):
        """检查密码

        :param value:
        """
        if len(value) < 4:
            raise serializers.ValidationError(u'密码太短')
        return value

    def validate(self, data):
        import pyotp

        request = self.context['request']
        user = request.user

        password = data['password']

        is_mobile_code_valid = models.SMSCode.check_code(
            mobile=user.mobile, code=password, context=models.SMSCode.CONTEXT_SAFETY)

        user_otp = models.UserOTP.get_user_otp(user)
        _otp = pyotp.TOTP(user_otp.secret)
        is_otp_code_valid = _otp.verify(password)

        if is_mobile_code_valid or is_otp_code_valid:
            data['uid'] = user.id  # 将 uid 传到视图函数中使用
            return data

        raise serializers.ValidationError({'password': [u'密码无效']})


class UserOTPChangeSerializer(serializers.Serializer):
    """OTP变更列化器"""

    code = serializers.CharField(max_length=16, error_messages={'required': u'验证码不能为空'})

    def validate_code(self, value):
        import pyotp

        request = self.context['request']
        user = request.user

        user_otp = models.UserOTP.get_user_otp(user)

        _otp = pyotp.TOTP(user_otp.secret)

        if not _otp.verify(value):
            raise serializers.ValidationError(u'验证码错误')

        return value


class UserChangeMobileSerializer(serializers.Serializer):
    """用户修改手机号码序列化器"""
    old_mobile = serializers.CharField(
        max_length=16, error_messages={'required': u'旧手机号码不能为空'})
    new_mobile = serializers.CharField(
        max_length=16, error_messages={'required': u'新手机号码不能为空'})
    code = serializers.CharField(
        max_length=16, error_messages={'required': u'验证码不能为空'})

    def validate_old_mobile(self, value):
        """检查旧手机号码

        :param value:
        """
        if not helpers.is_mobile(value):
            raise serializers.ValidationError(u'手机号码不符合要求')
        if not models.User.check_mobile_existed(value):
            raise serializers.ValidationError(u'手机号码未注册')
        return value

    def validate_new_mobile(self, value):
        """检查新手机号码

        :param value:
        """
        if not helpers.is_mobile(value):
            raise serializers.ValidationError(u'手机号码不符合要求')
        if models.User.check_mobile_existed(value):
            raise serializers.ValidationError(u'手机号码已经注册过')
        return value

    def validate(self, data):
        new_mobile = data['new_mobile']
        code = data['code']
        context = models.SMSCode.CONTEXT_TRANSFER

        if models.SMSCode.check_code(new_mobile, code, context):
            return data

        raise serializers.ValidationError({'code': u'验证码无效'})


class UserBindWeixinSerializer(serializers.Serializer):
    """用户绑定微信序列化器"""

    # OpenID 或 UnionID
    weixin_id = serializers.CharField(
        max_length=128, error_messages={'required': u'微信 OpenID 或 UnionID 不能为空.'})

    sort = serializers.ChoiceField(choices=models.UserWeixin.SORTS)

    def validate_sort(self, value):
        _sort = models.UserWeixin.get_weixin_id_sort()
        if value != _sort:
            raise serializers.ValidationError(u'微信 ID 类型与系统设置不匹配.')
        return value

    def validate(self, data):
        if models.UserWeixin.is_exists(data['sort'], data['weixin_id']):
            raise serializers.ValidationError({'weixin_id': u'微信 OpenID 或 UnionID 已绑定.'})
        return data


class SendSMSCodeSerializer(serializers.Serializer):
    """短信序列化器"""
    mobile = serializers.CharField(
        max_length=128, error_messages={'required': u'该字段不能为空'})
    #: 使用场景
    context = serializers.ChoiceField(choices=models.SMSCode.CONTEXTS, required=True)

    def validate_mobile(self, value):
        """检查手机号码

        :param value:
        """
        from . import helpers

        value = value.lower()

        if not helpers.is_mobile(value) and not helpers.is_email(value):
            raise serializers.ValidationError(u'该字段格式不符合要求')
        return value

    def validate(self, data):
        context = data.get('context', models.SMSCode.CONTEXT_REGISTER)
        mobile = data.get('mobile')
        qc = models.models.Q(mobile=mobile) | models.models.Q(email=mobile)
        user = models.User.objects.filter(qc).first()
        if context == models.SMSCode.CONTEXT_REGISTER:
            if user:
                raise serializers.ValidationError({'mobile': u'该账号已注册'})
        else:
            if not user:
                raise serializers.ValidationError({'mobile': u'该账号未注册'})
        return data


class CheckSMSCodeSerializer(serializers.Serializer):
    """检查短信序列化器"""

    #: 手机号
    mobile = serializers.CharField(
        max_length=128, error_messages={'required': u'该字段不能为空'})

    #: 验证码
    code = serializers.CharField(
        max_length=16, error_messages={'required': u'验证码不能为空'})

    #: 使用场景
    context = serializers.ChoiceField(choices=models.SMSCode.CONTEXTS, required=True)

    def validate_mobile(self, value):
        """检查手机号码

        :param value:
        """
        from . import helpers

        value = value.lower()

        if not helpers.is_mobile(value) and not helpers.is_email(value):
            raise serializers.ValidationError(u'该字段格式不符合要求')

        return value


class WeixinWebAuthSerializer(serializers.Serializer):
    """微信身份认证列化器"""
    code = serializers.CharField(max_length=64, error_messages={'required': u'code 不能为空'})


class WeixinBindSerializer(serializers.Serializer):
    """微信绑定证列化器"""
    openid = serializers.CharField(max_length=64, error_messages={'required': u'openid 不能为空'})

    def validate_openid(self, value):
        if models.User.objects.filter(wx_openid=value).first():
            raise serializers.ValidationError(u'OpenID 已经被绑定。')
        return value


class WeixinConfigSerializer(serializers.Serializer):
    """微信配置列化器"""

    url = serializers.URLField(max_length=256, error_messages={'required': u'url 不能为空'})

class UserInfoSerializer(serializers.Serializer):
    """用户信息"""
    fullname = serializers.CharField(
        max_length=128, error_messages={'required': u'姓名不能空'})
    #: 头像
    avatar = serializers.CharField(max_length=128, required=False)
    email = serializers.CharField(max_length=128, required=False)



class UserRegisterByMobileSerializer(serializers.Serializer):
    """用户注册序列化器"""
    nickname = serializers.CharField(
        max_length=128, error_messages={'required': u'请输入昵称'})
    mobile = serializers.CharField(
        max_length=128, error_messages={'required': u'该字段不能为空'})
    password = serializers.CharField(
        max_length=64, error_messages={'required': u'密码不能为空'})
    code = serializers.CharField(
        max_length=16, error_messages={'required': u'验证码不能为空'})

    def validate_mobile(self, value):
        """检查手机号码

        :param value:
        """
        from . import helpers

        value = value.lower()

        if not helpers.is_mobile(value) and not helpers.is_email(value):
            raise serializers.ValidationError(u'该字段格式不符合要求')
        if models.User.check_mobile_existed(value) or \
                models.User.check_email_existed(value):
            raise serializers.ValidationError(u'该账号已经注册')
        return value

    def validate_password(self, value):
        """检查密码

        :param value:
        """
        if len(value) < 6:
            raise serializers.ValidationError(u'密码太短')
        return value

    def validate(self, data):
        mobile = data['mobile']
        if helpers.is_email(mobile):
            mobile = helpers.md5_b16(mobile)

        code = data['code']
        context = models.SMSCode.CONTEXT_REGISTER

        if models.SMSCode.check_code(mobile, code, context):
            return data

        raise serializers.ValidationError({'code': u'验证码无效'})


class UserRegisterSerializer(serializers.Serializer):
    """用户注册序列化器"""

    username = serializers.CharField(
        max_length=64, error_messages={'required': u'用户名不能为空'})

    password = serializers.CharField(
        max_length=64, error_messages={'required': u'密码不能为空'})

    # 账号类型, 0-用户名, 1-邮箱, 2-手机号码, 3-微信openid
    typ = serializers.IntegerField(default=0)

    def validate_password(self, value):
        """检查密码

        :param value:
        """
        if len(value) < 6:
            raise serializers.ValidationError(u'密码太短')
        return value

    def validate(self, data):
        from django.core import validators
        from .helpers import is_mobile

        username = data['username']

        if is_mobile(username):
            data['typ'] = 2
            if models.User.check_mobile_existed(username):
                raise serializers.ValidationError({'username': [u'手机号码已经注册过']})

        try:
            validators.EmailValidator()(username)
            data['typ'] = 1
            if models.User.check_email_existed(username):
                raise serializers.ValidationError({'username': [u'邮箱已经注册过']})
        except validators.ValidationError:
            pass

        if models.User.check_username_existed(username):
            raise serializers.ValidationError({'username': [u'用户名已经注册过']})

        return data


class IsUserRegisteredSerializer(serializers.Serializer):
    """用户是否已经注册序列化器"""

    username = serializers.CharField(
        max_length=64, error_messages={'required': u'登录名不能为空'})
    type = serializers.CharField(
        max_length=32, error_messages={'required': u'类型不能为空'}
    )

    def validate_type(self, value):
        """检查类型

        :param value:
        """
        if value not in ('username', 'mobile', 'email', 'weixin'):
            raise serializers.ValidationError(u'类型不符合要求')
        return value

    def validate(self, data):
        if data['type'] == 'mobile':
            if not helpers.is_mobile(data['username']):
                raise serializers.ValidationError({'username': u'手机号码不符合要求'})
        return data


class UserChangePasswordSerializer(serializers.Serializer):
    """用户修改密码序列化器"""
    old_password = serializers.CharField(
        max_length=64, error_messages={'required': u'旧密码不能为空'})
    new_password = serializers.CharField(
        max_length=64, error_messages={'required': u'新密码不能为空'})

    def validate_old_password(self, value):
        """检查旧密码

        :param value:
        """
        if len(value) < 6:
            raise serializers.ValidationError(u'旧密码太短')
        return value

    def validate_new_password(self, value):
        """检查新密码

        :param value:
        """
        if len(value) < 6:
            raise serializers.ValidationError(u'新密码太短')
        return value


class UserForgetPasswordSerializer(serializers.Serializer):
    """用户忘记密码序列化器"""
    mobile = serializers.CharField(
        max_length=128, error_messages={'required': u'该字段不能为空'})
    code = serializers.CharField(
        max_length=16, error_messages={'required': u'验证码不能为空'})
    new_password = serializers.CharField(
        max_length=64, error_messages={'required': u'新密码不能为空'})

    def validate_mobile(self, value):
        """检查手机号码

        :param value:
        """
        from . import helpers

        value = value.lower()

        if not helpers.is_mobile(value) and not helpers.is_email(value):
            raise serializers.ValidationError(u'该字段格式不符合要求')
        if not models.User.check_mobile_existed(value) and \
                not models.User.check_email_existed(value):
            raise serializers.ValidationError(u'该账号未注册')
        return value

    def validate_new_password(self, value):
        """检查新密码

        :param value:
        """
        if len(value) < 6:
            raise serializers.ValidationError(u'新密码太短')
        return value

    def validate(self, data):
        mobile = data['mobile']
        if helpers.is_email(mobile):
            mobile = helpers.md5_b16(mobile)

        code = data['code']
        context = models.SMSCode.CONTEXT_FORGET

        if models.SMSCode.check_code(mobile, code, context):
            return data

        raise serializers.ValidationError({'code': u'验证码错误'})


class EmailResendConfirmationSerializer(serializers.Serializer):

    email = serializers.EmailField(max_length=128, required=True, allow_blank=False)

    def validate_email(self, value):
        user = models.User.objects.filter(email=value).first()
        if not user:
            raise serializers.ValidationError(u'邮件地址未注册')
        if user.email_confirmed:
            raise serializers.ValidationError(u'邮件地址已确认')
        return value


class EmailResendConfirmSerializer(serializers.Serializer):

    token = serializers.CharField(max_length=255, required=True, allow_blank=False)

    def validate_token(self, value):
        from urllib import parse
        from django.core import signing

        email_confirm_exp = getattr(settings, 'EMAIL_CONFIRM_EXPIRATION', None) or 3600

        value = parse.unquote_plus(value)

        try:
            signing.loads(value, max_age=email_confirm_exp)
            return value
        except signing.SignatureExpired:
            raise serializers.ValidationError(u'token 已过期')
        except signing.BadSignature:
            raise serializers.ValidationError(u'token 无效')
