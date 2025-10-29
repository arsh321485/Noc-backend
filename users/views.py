# # users/views.py
# from rest_framework import generics, status, permissions
# from rest_framework.response import Response
# from .serializers import (
#     UserRegistrationSerializer, UserLoginSerializer,
#     UserProfileSerializer, UserUpdateSerializer,
#     ChangePasswordSerializer,PasswordResetRequestSerializer,
#     PasswordResetConfirmSerializer
# )
# from .models import User
# from rest_framework.permissions import AllowAny, IsAuthenticated
# from rest_framework_simplejwt.tokens import RefreshToken
# from django.contrib.auth import login, logout
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.views import APIView
# from .utils import send_reset_email


# User = get_user_model()
# token_generator = PasswordResetTokenGenerator()

# # Environment / settings - where frontend will accept uid & token
# FRONTEND_RESET_URL = getattr(settings, "FRONTEND_RESET_URL", "http://localhost:8080/reset-password") 
# # Example final URL: http://frontend/reset-password?uid=...&token=...

# def get_tokens_for_user(user):
#     refresh = RefreshToken.for_user(user)
#     return {
#         "refresh": str(refresh),
#         "access": str(refresh.access_token)
#     }

# class UserRegistrationView(generics.CreateAPIView):
#     queryset = User.objects.all()
#     serializer_class = UserRegistrationSerializer
#     permission_classes = (AllowAny,)

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         user = serializer.save()
#         tokens = get_tokens_for_user(user)
#         return Response({
#             "message": "User registered",
#             "user": UserProfileSerializer(user).data,
#             "tokens": tokens
#         }, status=status.HTTP_201_CREATED)

# class UserLoginView(generics.GenericAPIView):
#     permission_classes = (AllowAny,)
#     serializer_class = UserLoginSerializer

#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data["user"]
#         login(request, user)
#         tokens = get_tokens_for_user(user)
#         return Response({
#             "message": "Login successful",
#             "user": UserProfileSerializer(user).data,
#             "tokens": tokens
#         }, status=status.HTTP_200_OK)

# class UserProfileView(generics.RetrieveAPIView):
#     permission_classes = (IsAuthenticated,)
#     serializer_class = UserProfileSerializer

#     def get_object(self):
#         return self.request.user

#     def retrieve(self, request, *args, **kwargs):
#         user = self.get_object()
#         serializer = self.get_serializer(user)
#         return Response({
#             "message": "Profile retrieved successfully",
#             "user": serializer.data
#         }, status=status.HTTP_200_OK)



# class UserProfileUpdateView(generics.UpdateAPIView):
#     permission_classes = (IsAuthenticated,)
#     serializer_class = UserUpdateSerializer

#     def get_object(self):
#         return self.request.user

#     def patch(self, request, *args, **kwargs):
#         kwargs['partial'] = True
#         return self.update(request, *args, **kwargs)

#     def update(self, request, *args, **kwargs):
#         partial = kwargs.pop('partial', True)
#         instance = self.get_object()
#         serializer = self.get_serializer(instance, data=request.data, partial=partial)
#         serializer.is_valid(raise_exception=True)
#         self.perform_update(serializer)

#         # Always refresh instance to reflect updated_at & last_login correctly
#         instance.refresh_from_db()

#         return Response({
#             "message": "Profile updated successfully",
#             "user": serializer.data
#         }, status=status.HTTP_200_OK)




# @api_view(["POST"])
# @permission_classes([permissions.AllowAny])
# def logout_view(request):
#     try:
#         # If you want to blacklist refresh tokens, handle them here.
#         logout(request)
#     except Exception:
#         pass
#     return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)


# class ChangePasswordView(APIView):
#     permission_classes = (IsAuthenticated,)

#     def post(self, request, *args, **kwargs):
#         serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
#         serializer.is_valid(raise_exception=True)

#         user = serializer.save()

#         # Optionally: if you use JWT and want to force logout, blacklist refresh tokens here.
#         # Example comment: blacklist tokens or notify user.

#         return Response({
#             "message": "Password changed successfully",
#             "user": {
#                 "id": getattr(user, "id", None),
#                 "email": getattr(user, "email", None)
#             }
#         }, status=status.HTTP_200_OK)
        
        
# class PasswordResetRequestView(APIView):
#     permission_classes = (permissions.AllowAny,)

#     def post(self, request):
#         serializer = PasswordResetRequestSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         email = serializer.validated_data["email"]

#         # Try to find the user (if exists)
#         try:
#             user = User.objects.get(email__iexact=email)
#         except User.DoesNotExist:
#             user = None

#         # Regardless of whether user exists, respond with same message (no email leak)
#         if user:
#             uid = urlsafe_base64_encode(force_bytes(user.pk))
#             token = token_generator.make_token(user)

#             # Build frontend reset link with uid & token
#             reset_link = f"{FRONTEND_RESET_URL}?uid={uid}&token={token}"

#             # Render email body (you can use templates)
#             subject = "Reset your password"
#             html_content = f"""
#             <p>Hello {user.firstname or user.email},</p>
#             <p>You requested a password reset. Click the link below to set a new password.</p>
#             <p><a href="{reset_link}">Reset password</a></p>
#             <p>If you didn't ask for this, ignore this email.</p>
#             """
#             plain_text = f"Reset your password: {reset_link}"

#             try:
#                 send_reset_email(user.email, subject, html_content, plain_text=plain_text)
#             except Exception as e:
#                 # Log exception in production; do not reveal sensitive internals to client
#                 return Response({"error": "Failed to send email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#         # Always return same response to avoid leaking whether email exists
#         return Response({"message": "If an account with that email exists, we sent a password reset email."}, status=status.HTTP_200_OK)


# class PasswordResetConfirmView(APIView):
#     permission_classes = (permissions.AllowAny,)

#     def post(self, request):
#         serializer = PasswordResetConfirmSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         uidb64 = serializer.validated_data["uid"]
#         token = serializer.validated_data["token"]
#         new_password = serializer.validated_data["new_password"]

#         # Decode uid
#         try:
#             uid = force_str(urlsafe_base64_decode(uidb64))
#             user = User.objects.get(pk=uid)
#         except Exception:
#             return Response({"error": "Invalid uid/token"}, status=status.HTTP_400_BAD_REQUEST)

#         # Verify token
#         if not token_generator.check_token(user, token):
#             return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

#         # All good — set password
#         user.set_password(new_password)
#         user.save()

#         # Optional: blacklist JWT tokens for this user (if you want to invalidate sessions)
#         # You can call a utility that blacklists user's refresh tokens.
#         return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)


# users/views.py
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
from .utils import send_reset_email

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

        # Try to find the user (if exists)
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            user = None

        # Regardless of whether user exists, respond with same message (no email leak)
        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = token_generator.make_token(user)

            # Build frontend reset link with uid & token
            reset_link = f"{FRONTEND_RESET_URL}?uid={uid}&token={token}"

            subject = "Reset your password"
            html_content = f"""
            <p>Hello {user.firstname or user.email},</p>
            <p>You requested a password reset. Click the link below to set a new password.</p>
            <p><a href="{reset_link}">Reset password</a></p>
            <p>If you didn't ask for this, ignore this email.</p>
            """
            plain_text = f"Reset your password: {reset_link}"

            try:
                send_reset_email(user.email, subject, html_content, plain_text=plain_text)
            except Exception:
                return Response({"error": "Failed to send email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "If an account with that email exists, we sent a password reset email."}, status=status.HTTP_200_OK)


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
