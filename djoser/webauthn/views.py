from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from webauthn import (
    WebAuthnAssertionOptions,
    WebAuthnAssertionResponse,
    WebAuthnMakeCredentialOptions,
    WebAuthnRegistrationResponse,
    WebAuthnUser,
)

from djoser.conf import settings

from .models import CredentialOptions
from .serializers import (
    WebauthnCredentailSerializer,
    WebauthnLoginSerializer,
    WebauthnSignupSerializer,
)
from .utils import create_challenge

User = get_user_model()


# SignupOptionsView?
class SingupRequestView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = WebauthnSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        co = serializer.save()

        credential_registration_dict = WebAuthnMakeCredentialOptions(
            challenge=co.challenge,
            rp_name=settings.WEBAUTHN["RP_NAME"],
            rp_id=settings.WEBAUTHN["RP_ID"],
            user_id=co.ukey,
            username=co.username,
            display_name=co.display_name,
            icon_url="",
        )

        return Response(credential_registration_dict.registration_dict)


# SignupView?
class SignupVerifyView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = WebauthnCredentailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            co = CredentialOptions.objects.get(ukey=serializer.validated_data["ukey"])
        except CredentialOptions.DoesNotExist:
            return Response(
                {"error": "Invalid ukey."}, status=status.HTTP_400_BAD_REQUEST
            )

        webauthn_registration_response = WebAuthnRegistrationResponse(
            rp_id=settings.WEBAUTHN["RP_ID"],
            origin=settings.WEBAUTHN["ORIGIN"],
            registration_response=request.data,
            challenge=co.challenge,
            none_attestation_permitted=True,
        )
        try:
            webauthn_credential = webauthn_registration_response.verify()
        except Exception as e:
            return Response(
                {"error": "Registration failed. Error: {}".format(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(username=co.username).exists():
            return Response(
                {"error": "User {} already exists.".format(co.username)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.create(username=co.username)

        serializer.save(
            user=user,
            sign_count=webauthn_credential.sign_count,
            credential_id=webauthn_credential.credential_id.decode(),
            public_key=webauthn_credential.public_key.decode(),
        )

        return Response({"success": True})


class LoginRequestView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = WebauthnLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        co = CredentialOptions.objects.get(
            username=serializer.validated_data["username"]
        )

        co.challenge = create_challenge(32)
        co.save()

        webauthn_user = WebAuthnUser(
            user_id=co.ukey,
            username=co.username,
            display_name=co.display_name,
            icon_url="",
            credential_id=co.credential_id,
            public_key=co.public_key,
            sign_count=co.sign_count,
            rp_id=settings.WEBAUTHN["RP_ID"],
        )
        webauthn_assertion_options = WebAuthnAssertionOptions(
            webauthn_user, co.challenge
        )

        return Response(webauthn_assertion_options.assertion_dict)


# this name looks good :)
class LoginView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = WebauthnLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]

        try:
            user = User.objects.filter(username=username).first()
        except User.DoesNotExist:
            return Response({"error": "User {} does not exist.".format(username)})

        co = user.credential_options

        webuathn_user = WebAuthnUser(
            user_id=co.ukey,
            username=user.username,
            display_name=co.display_name,
            icon_url="",
            credential_id=co.credential_id,
            public_key=co.public_key,
            sign_count=co.sign_count,
            rp_id=settings.WEBAUTHN["RP_ID"],
        )

        webauthn_assertion_response = WebAuthnAssertionResponse(
            webuathn_user,
            request.data,
            co.challenge,
            settings.WEBAUTHN["ORIGIN"],
            uv_required=False,
        )

        try:
            sign_count = webauthn_assertion_response.verify()
        except Exception as e:
            return Response(
                {"error": "Assertion failed. Error: {}".format(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        co.sign_count = sign_count
        co.save()

        return Response({"auth_token": "TOKEN_GOES_HERE"})
