from django.urls import path

from . import views

urlpatterns = [
    path(
        "get_credential_options/",
        views.SingupRequestView.as_view(),
        name="get_credential_options",
    ),
    path(
        "verify_credential_info/",
        views.SignupVerifyView.as_view(),
        name="verify_credential_info",
    ),
    path("begin_login/", views.LoginRequestView.as_view(), name="begin_login"),
    path("login/", views.LoginView.as_view(), name="login"),
]
