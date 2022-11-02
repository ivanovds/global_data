from django.contrib.auth import get_user_model
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework import status
from django.db.models import ProtectedError

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
                raise ValidationError({'errors': [f'Model {model_name} does not exist!']})

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
                return self.__perform_change(model_class, fid, model_data)
            elif action == 'create':
                return self.__perform_create(model_class, fid, model_data)
            elif action == 'delete':
                return self.__perform_delete(model_class, fid)
            else:
                raise ValidationError({'errors': [f'Invalid action - {action}']})
        else:
            raise ValidationError({'errors': serializer.errors})

    @staticmethod
    def __perform_create(model_class, fid, model_data):
        model_class.objects.get_or_create(
            fid=fid,
            defaults=model_data)

        return Response(
            data={'ok': True, 'msg': f'The object of model {model_class.__name__} with fid {fid} was created'}
        )

    @staticmethod
    def __perform_change(model_class, fid, model_data):
        try:
            obj = model_class.objects.get(fid=fid)
        except model_class.DoesNotExist:
            return Response(
                data=f'The object of model {model_class.__name__} with fid {fid} does not exist in MSW',
                status=status.HTTP_404_NOT_FOUND
            )

        for field, value in model_data.items():
            setattr(obj, field, value)
        obj.save()

        return Response(
            data={'ok': True, 'msg': f'The object of model {model_class.__name__} with fid {fid} was changed'}
        )

    @staticmethod
    def __perform_delete(model_class, fid):
        try:
            obj = model_class.objects.get(fid=fid)
        except model_class.DoesNotExist:
            return Response(
                data=f'The object of model {model_class.__name__} with fid {fid} does not exist in MSW',
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            obj.delete()
        except ProtectedError:
            return Response(
                data='The object could not be deleted because of the associated models',
                status=status.HTTP_409_CONFLICT
            )

        return Response(
            data={'ok': True, 'msg': f'The object of model {model_class.__name__} with fid {fid} was deleted'},
            status=status.HTTP_200_OK
        )
