import json
from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework.response import Response

from .serializers import UserAdminSerializer
from .authentication import BearerAuthentication
from .permissions import IsUserAuthenticated
from djangorestframework_camel_case.render import CamelCaseJSONRenderer
from djangorestframework_camel_case.parser import CamelCaseJSONParser
from .models import User



class UserAdminListViewSet(viewsets.ModelViewSet, viewsets.GenericViewSet):
    serializer_class = UserAdminSerializer
    authentication_classes = [BearerAuthentication, ]
    permission_classes = [BearerAuthentication, ]
    renderer_classes =  (CamelCaseJSONRenderer,)
    def get_queryset(self):
        status=self.request.GET.get("status")
        qs=User.objects.all()
        if status:
            qs=qs.filter(status=status)
        return qs
