# -*- coding: utf-8 -*-

from django.conf.urls import include, url

from .user_admin_views import UserAdminListViewSet


user_admin_list=UserAdminListViewSet.as_view({
    "get":"get"
})


urlpatterns = (
    url(r'^user$', user_admin_list, name='user-admin-list'),

)
