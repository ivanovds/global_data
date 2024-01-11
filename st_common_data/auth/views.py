from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from django.core.exceptions import FieldDoesNotExist
from django.db.models import Q
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import GenericViewSet, ModelViewSet
from rest_framework.decorators import action
from rest_framework.response import Response

from st_common_data.auth.django_auth import Auth0ServiceAuthentication
from st_common_data.auth.serializers import Auth0NewUserSerializer, NewUserResponseSerializer
from st_common_data.utils.common import get_current_kyiv_datetime

UserModel = get_user_model()


class Auth0ViewSet(GenericViewSet):
    """Views for requests from Auth0 server"""
    authentication_classes = (Auth0ServiceAuthentication, )
    permission_classes = (IsAuthenticated, )
    serializer_class = NewUserResponseSerializer

    @action(detail=False, methods=['POST'])
    def new_user(self, request, *args, **kwargs):
        """
        After creation user in auth0 create new in our DB
        or set auth0 field for existing users based on their email

        user object would be next structure:
        {
            email: 'sample@domain.com',
            tenant: 'our_tenant',
            user_id: 'auth0|some_user_id',
            app_metadata: {},
            user_metadata: {},
            created_at: undefined,
            updated_at: undefined,
            email_verified: false,
            phone_verified: false
        }
        """

        serializer = Auth0NewUserSerializer(data=request.data)
        if serializer.is_valid():
            user_data = serializer.validated_data['new_user']
            try:
                user_id_list = user_data['user_id'].split('|')
                auth_provider = user_id_list[0]
                if auth_provider != 'auth0':
                    raise
                auth0_id = user_id_list[1]
                email = user_data['email']
            except Exception:
                raise ValidationError({'errors': [{'user_id': 'Invalid or missing user_id'}]})

            try:
                user = UserModel.objects.get(Q(email=email) | Q(auth0=auth0_id))
                user.auth0 = auth0_id
                user.email = email
                user.username = email
                user.first_name = user_data.get('first_name', user.first_name)
                user.last_name = user_data.get('last_name', user.last_name)
                user.first_name_en = user_data.get('first_name_en', user.first_name_en)
                user.last_name_en = user_data.get('last_name_en', user.last_name_en)
                user.hr_id = user_data.get('hr_id', user.hr_id)
                user.save()
            except UserModel.DoesNotExist:
                user_data = {
                    'username': email,
                    'email': email,
                    'auth0': auth0_id,
                    'first_name': user_data.get('first_name', ''),
                    'last_name': user_data.get('last_name', ''),
                    'first_name_en': user_data.get('first_name_en', ''),
                    'last_name_en': user_data.get('last_name_en', ''),
                    'hr_id': user_data.get('hr_id'),
                }

                try:  # specify first_work_day if this filed exists in UserModel
                    UserModel._meta.get_field('first_work_day')
                    today = get_current_kyiv_datetime().date()
                    user_data['first_work_day'] = today
                except FieldDoesNotExist:
                    pass

                user = UserModel.objects.create_user(**user_data)
            except UserModel.MultipleObjectsReturned:
                raise ValidationError({'errors': f'There are more then one user '
                                                 f'with email {email} and auth0_id {auth0_id}'})

            response_serializer = self.serializer_class(user)
            return Response(response_serializer.data)

        else:
            raise ValidationError({'errors': serializer.errors})
