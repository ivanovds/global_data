from django.contrib.auth import get_user_model
from rest_framework import serializers

UserModel = get_user_model()


class Auth0NewUserSerializer(serializers.Serializer):
    new_user = serializers.JSONField()


class NewUserResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ('id', 'auth0', 'email', 'username', 'date_joined',)