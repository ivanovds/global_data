from rest_framework import serializers


class UpdateFomAccManSerializer(serializers.Serializer):
    model_name = serializers.CharField()
    action = serializers.CharField()
    changes = serializers.JSONField()
