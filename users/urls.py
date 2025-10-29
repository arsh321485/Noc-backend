# users/urls.py
from django.urls import path
from .views import (
    UserRegistrationView, UserLoginView, UserProfileView,
    UserProfileUpdateView, logout_view,ChangePasswordView,
    PasswordResetRequestView,PasswordResetConfirmView,
)

urlpatterns = [
    path("signup/", UserRegistrationView.as_view(), name="signup"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("logout/", logout_view, name="logout"),
    path("profile/", UserProfileView.as_view(), name="profile"),
    path("profile/update/", UserProfileUpdateView.as_view(), name="profile-update"),
    path("profile/change-password/", ChangePasswordView.as_view(), name="change-password"),
    path("password/forgot/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password/reset/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
]
