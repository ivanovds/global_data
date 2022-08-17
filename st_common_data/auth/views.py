from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import GenericViewSet, ModelViewSet
from rest_framework.decorators import action
from rest_framework.response import Response

from st_common_data.auth.django_auth import Auth0ServiceAuthentication
from st_common_data.auth.serializers import Auth0NewUserSerializer, NewUserResponseSerializer

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
            try:
                user_id_list = serializer.validated_data['new_user']['user_id'].split('|')
                auth_provider = user_id_list[0]
                if auth_provider != 'auth0':
                    raise
                auth0_id = user_id_list[1]
                email = serializer.validated_data['new_user']['email']
            except Exception:
                raise ValidationError({'errors': [{'user_id': 'Invalid or missing user_id'}]})

            try:
                user = UserModel.objects.get(auth0=auth0_id)

                response_serializer = self.serializer_class(user)
                return Response(response_serializer.data)
            except UserModel.DoesNotExist:
                pass

            try:
                user = UserModel.objects.get(email=email)
                user.auth0 = auth0_id
                user.save()
            except UserModel.DoesNotExist:
                user = UserModel.objects.create_user(
                    username=email,
                    email=email,
                    auth0=auth0_id)

            response_serializer = self.serializer_class(user)
            return Response(response_serializer.data)

        else:
            raise ValidationError({'errors': serializer.errors})
