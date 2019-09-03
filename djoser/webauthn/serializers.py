from django.contrib.auth import get_user_model
from rest_framework import serializers

from djoser.conf import settings

from .models import CredentialOptions
from .utils import create_challenge, create_ukey

User = get_user_model()


class WebauthnSignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = CredentialOptions
        fields = ("username", "display_name")

    def create(self, validated_data):
        validated_data.update(
            {
                "challenge": create_challenge(
                    length=settings.WEBAUTHN["CHALLENGE_LENGTH"]
                ),
                "ukey": create_ukey(length=settings.WEBAUTHN["UKEY_LENGTH"]),
            }
        )
        return super().create(validated_data)

    def validate_username(self, username):
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                "User {} already exists.".format(username)
            )
        return username


class WebauthnCredentailSerializer(serializers.Serializer):
    ukey = serializers.CharField()


class WebauthnLoginSerializer(serializers.Serializer):
    username = serializers.CharField()

    def validate_username(self, username):
        if not User.objects.filter(
            username=username, credential_options__isnull=False
        ).exists():
            raise serializers.ValidationError(
                "User {} does not exist or has not been registered via webauthn.".format(
                    username
                )
            )
        return username
