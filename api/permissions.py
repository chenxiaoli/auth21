# -*- coding: utf-8 -*-
"""自定义 API 授权(权限)方式"""

from rest_framework import permissions

from . import models


class IsUserAuthenticated(permissions.BasePermission):
    """只允许身份已验证的用户访问"""
    def has_permission(self, request, view):
        return isinstance(request.user, models.User)
