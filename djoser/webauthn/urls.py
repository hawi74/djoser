from django.urls import path

from . import views

app_name = "djoser.webauthn"

urlpatterns = [
    path("signup_request/", views.SingupRequestView.as_view(), name="signup_request"),
    path("signup/<ukey>/", views.SignupView.as_view(), name="signup"),
    path("login_request/", views.LoginRequestView.as_view(), name="login_request"),
    path("login/", views.LoginView.as_view(), name="login"),
]
