from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
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


class WebauthnCreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = tuple(User.REQUIRED_FIELDS) + (
            settings.LOGIN_FIELD,
            User._meta.pk.name,
        )

    # TODO: those methods are exactly the same as in djoser.serializers.UserCreateSerializer
    # maybe extract them to a common base or a mixin?
    def create(self, validated_data):
        try:
            user = self.perform_create(validated_data)
        except IntegrityError:
            self.fail("cannot_create_user")

        return user

    def perform_create(self, validated_data):
        with transaction.atomic():
            user = User.objects.create_user(**validated_data)
            if settings.SEND_ACTIVATION_EMAIL:
                user.is_active = False
                user.save(update_fields=["is_active"])
        return user


class WebauthnLoginSerializer(serializers.Serializer):
    default_error_messages = {
        "invalid_credentials": settings.CONSTANTS.messages.INVALID_CREDENTIALS_ERROR
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields[settings.LOGIN_FIELD] = serializers.CharField(required=True)

    def validate_username(self, username):
        try:
            search_kwargs = {
                settings.LOGIN_FIELD: username,
                "credential_options__isnull": False,
            }
            self.user = user = User.objects.get(**search_kwargs)
        except User.DoesNotExist:
            self.fail("invalid_credentials")

        if not user.is_active:
            self.fail("invalid_credentials")

        return username
