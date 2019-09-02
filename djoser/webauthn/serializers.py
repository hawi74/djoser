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


class WebauthnCredentailSerializer(serializers.ModelSerializer):
    class Meta:
        model = CredentialOptions
        fields = ("ukey",)

    ukey = serializers.CharField()


class WebauthnLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
