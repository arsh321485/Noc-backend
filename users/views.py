from venv import logger
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string

from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer,
    UserProfileSerializer, UserUpdateSerializer,
    ChangePasswordSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)
from .models import User
from .utils import send_reset_email,SendEmailError

# convenience
User = get_user_model()
token_generator = PasswordResetTokenGenerator()

# Environment / settings - where frontend will accept uid & token
FRONTEND_RESET_URL = getattr(settings, "FRONTEND_RESET_URL", "http://localhost:8080/reset-password")

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token)
    }

# --- Your views (unchanged logic; imports fixed) ---

class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = (AllowAny,)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        tokens = get_tokens_for_user(user)
        return Response({
            "message": "User registered",
            "user": UserProfileSerializer(user).data,
            "tokens": tokens
        }, status=status.HTTP_201_CREATED)


class UserLoginView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        login(request, user)
        tokens = get_tokens_for_user(user)
        return Response({
            "message": "Login successful",
            "user": UserProfileSerializer(user).data,
            "tokens": tokens
        }, status=status.HTTP_200_OK)


class UserProfileView(generics.RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserProfileSerializer

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user)
        return Response({
            "message": "Profile retrieved successfully",
            "user": serializer.data
        }, status=status.HTTP_200_OK)


class UserProfileUpdateView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserUpdateSerializer

    def get_object(self):
        return self.request.user

    def patch(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Always refresh instance to reflect updated_at & last_login correctly
        instance.refresh_from_db()

        return Response({
            "message": "Profile updated successfully",
            "user": serializer.data
        }, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([permissions.AllowAny])
def logout_view(request):
    try:
        # If you want to blacklist refresh tokens, handle them here.
        logout(request)
    except Exception:
        pass
    return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        # Optionally: if you use JWT and want to force logout, blacklist refresh tokens here.

        return Response({
            "message": "Password changed successfully",
            "user": {
                "id": getattr(user, "id", None),
                "email": getattr(user, "email", None)
            }
        }, status=status.HTTP_200_OK)


class PasswordResetRequestView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        # Find user if exists (do not leak)
        user = User.objects.filter(email__iexact=email).first()
        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_link = f"{settings.FRONTEND_RESET_URL}?uid={uid}&token={token}"

            subject = "Reset your password"
            html_content = f"""
                <p>Hello {user.firstname or user.email},</p>
                <p>Click to reset password:</p>
                <p><a href="{reset_link}">Reset password</a></p>
                <p>If you didn't request this, ignore this email.</p>
            """
            plain_text = f"Reset your password: {reset_link}"

            try:
                ok = send_reset_email(user.email, subject, html_content, plain_text)
                if not ok:
                    # log, but don't expose details
                    logger.error("SendGrid returned non-success when sending to %s", user.email)
            except SendEmailError as e:
                logger.exception("Send reset email failed for %s: %s", user.email, e)
                # do not return 500 or reveal details to client

        # Always return the same message for security
        return Response(
            {"message": "If an account with that email exists, a password reset link has been sent."},
            status=status.HTTP_200_OK
        )
class PasswordResetConfirmView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uidb64 = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        # Decode uid
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"error": "Invalid uid/token"}, status=status.HTTP_400_BAD_REQUEST)

        # Verify token
        if not token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        # All good — set password
        user.set_password(new_password)
        user.save()

        # Optional: blacklist JWT tokens for this user (if you want to invalidate sessions)
        return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)
