from django.contrib.auth import get_user_model
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from st_common_data.auth.django_auth import Auth0ServiceAuthentication
from st_common_data.trading_accounts import models
from st_common_data.trading_accounts.serializers import UpdateFomAccManSerializer

UserModel = get_user_model()


class UpdateFomAccManView(GenericAPIView):
    """
    Subscription for updates from Account Management system
    """
    authentication_classes = (Auth0ServiceAuthentication, )
    permission_classes = (IsAuthenticated, )
    serializer_class = UpdateFomAccManSerializer

    def post(self, request):
        serializer = UpdateFomAccManSerializer(data=request.data)
        if serializer.is_valid():
            model_name = serializer.validated_data['model_name']
            action = serializer.validated_data['action']
            data = serializer.validated_data['changes']

            # Get model for updates/creation
            model_class = getattr(models, model_name, None)
            if not model_class:
                raise ValidationError({'errors': [f'Model {model_name} deos not exist!']})

            fid = data['fid']
            model_data = dict()
            for field, value in data.items():
                if isinstance(value, dict):
                    if 'auth0' in value:
                        model_data[field] = UserModel.objects.get(auth0=value['auth0'])
                    else:
                        related_model_class = getattr(models, value['model'])
                        model_data[field] = related_model_class.objects.get(fid=value['fid'])
                elif field != 'fid':
                    model_data[field] = value

            if action == 'change':
                model_class.objects.filter(fid=fid).update(**model_data)
            elif action == 'create':
                model_class.objects.get_or_create(
                    fid=fid,
                    defaults=model_data)
            else:
                raise ValidationError({'errors': [f'Invalid action - {action}']})

            return Response({'ok': True})

        else:
            raise ValidationError({'errors': serializer.errors})
