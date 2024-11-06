from account.models import User
from django.core.exceptions import ValidationError
from rest_framework.viewsets import GenericViewSet
from rest_framework import mixins
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
from account.serializers import (
    UserRegisterSerializer,
    LoginUserSerializer,
    PasswordResetSerializer,
    SetNewPasswordSerializer,
    LogoutUserSerializer,
    VerifyOTPSerializer,
    ResendVerificationOTPSerializer,
    UserSerializer
)

User = get_user_model()


class UserViewSet(GenericViewSet,):
    permission_classes = (IsAuthenticated,)
    queryset = User.objects.all()

    def get_serializer_class(self):
        if self.action == "logout":
            return LogoutUserSerializer
        elif self.action == "change_password":
            return SetNewPasswordSerializer
        elif self.action in ["register"]:
            return UserRegisterSerializer
        elif self.action in ["request_password_reset"]:
            return PasswordResetSerializer
        elif self.action in ["verify_email"]:
            return VerifyOTPSerializer
        elif self.action == "login":
            return LoginUserSerializer
        elif self.action == "resend_verification_otp":
            return ResendVerificationOTPSerializer
        else:
            return UserSerializer

    def get_queryset(self):
        return User.objects.filter(pk=self.request.user.pk)

    @action(methods=["post"], detail=False, permission_classes=(AllowAny,))
    def login(self, request):
        """Login user and return user data and token"""
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=["post"], detail=False, permission_classes=(AllowAny,))
    def register(self, request):
        """Register user and return user data and token"""
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(methods=["post"], detail=False, permission_classes=(AllowAny,))
    def change_password(self, request):
        """Change user password"""
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Password change successful"}, status=status.HTTP_200_OK)

    @action(
        methods=["post"],
        detail=False,
        permission_classes=(IsAuthenticated,),
    )
    def logout(self, request):
        """Logout user and deactivate tokens"""
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Log out successful"}, status=status.HTTP_200_OK)

    def get_object(self):
        """Return user object"""
        return self.request.user

    @action(["post"], detail=False, permission_classes=(AllowAny,))
    def request_password_reset(self, request, *args, **kwargs):
        """ Request for password reset"""
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Reset token sent to your mail"}, status=status.HTTP_200_OK)

    @action(["post"], detail=False, permission_classes=(AllowAny,))
    def verify_email(self, request, *args, **kwargs):
        """Verify Email"""
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Verification successful"}, status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, permission_classes=(AllowAny,))
    def resend_verification_otp(self, request, *args, **kwargs):
        """ Resend verification otp"""
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Verification OTP sent to your mail"}, status=status.HTTP_200_OK)
