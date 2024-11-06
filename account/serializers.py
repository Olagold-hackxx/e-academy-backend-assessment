from rest_framework import serializers
from .models import User, OneTimePassword
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from account.tasks import send_verification_email
from account.utils.otp import generate_otp, generate_otp_secret, verify_otp
from django.utils import timezone
from datetime import timedelta


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
        read_only_fields = ("id", "is_superuser", "is_staff")


class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    confirm_password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = [
            "email",
            "first_name",
            "last_name",
            "password",
            "confirm_password",

        ]

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        user = User.objects.create_user(**validated_data)
        secret_key = generate_otp_secret()
        print(secret_key)
        otp = generate_otp(secret_key)
        expires_at = timezone.now() + timedelta(minutes=5)
        # Hash the OTP before saving it
        otp_instance = OneTimePassword(
            user=user, code=otp, secret_key=secret_key, expires_at=expires_at)
        otp_instance.code = otp_instance.encrypt_code(
            otp)  # Encrypt the OTP
        otp_instance.save()
        subject = "Account Verification"
        message = f"Your verification code is {otp}"
        send_verification_email.delay(user.email, subject, message)
        return user


class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    password = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "access_token", "refresh_token", "id"]

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        request = self.context.get("request")
        self.user = authenticate(request, email=email, password=password)
        if not self.user:
            raise AuthenticationFailed("Invalid credentials, try again")
        if not self.user.is_verified:
            raise AuthenticationFailed("Email is not verified")

        attrs["user"] = self.user
        return attrs

    def to_representation(self, instance):
        tokens = self.user.tokens()
        return {
            "access_token": str(tokens.get("access")),
            "refresh_token": str(tokens.get("refresh")),
            "user": UserSerializer(self.user, context=self.context).data,
        }


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        email = attrs.get("email")
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            token = PasswordResetTokenGenerator().make_token(user)
            subject = "Password Reset Request"
            message = f"Your password reset token is {token}"
            send_verification_email.delay(user.email, subject, message)
        return super().validate(attrs)


class ResendVerificationOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        email = attrs.get("email")
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            secret_key = generate_otp_secret()
            print(secret_key)
            otp = generate_otp(secret_key)
            print(otp)
            expires_at = timezone.now() + timedelta(minutes=5)
            otp_instance, _ = OneTimePassword.objects.update_or_create(
                user=user,  # Match by user field
                defaults={
                    'code': otp,
                    'secret_key': secret_key,
                    'expires_at': expires_at
                }
            )
            otp_instance.code = otp_instance.encrypt_code(
                otp)  # Encrypt the OTP
            otp_instance.save()
            subject = "Account Verification"
            message = f"Your verification code is {otp}"
            send_verification_email.delay(user.email, subject, message)
            return super().validate(attrs)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=100, min_length=6, write_only=True)
    confirm_password = serializers.CharField(
        max_length=100, min_length=6, write_only=True
    )
    email = serializers.EmailField(write_only=True)
    token = serializers.CharField(write_only=True)

    class Meta:
        fields = ["password", "confirm_password", "token"]

    def validate(self, attrs):
        try:
            token = attrs.get("token")
            email = attrs.get("email")
            password = attrs.get("password")
            confirm_password = attrs.get("confirm_password")

            user = User.objects.get(email=email)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed(
                    "Reset token is invalid or has expired", 401)
            if password != confirm_password:
                raise AuthenticationFailed("Passwords do not match")
            user.set_password(password)
            user.save()
            return super().validate(attrs)
        except Exception as e:
            raise AuthenticationFailed(f"Failed to reset password: {e}")


class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    default_error_messages = {"bad_token": "Token is invalid or has expired"}

    def validate(self, attrs):
        self.token = attrs.get("refresh_token")
        return attrs  # Make sure to return attrs after validation

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            self.fail("bad_token")


class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField()
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        email = attrs.get("email")
        otp = attrs.get("otp")
        user_code_obj = OneTimePassword.objects.get(user__email=email)
        decrypted_code = user_code_obj.decrypt_code(user_code_obj.code)
        secret_key = str(user_code_obj.secret_key)
        print(secret_key)
        try:
            if decrypted_code == otp and not user_code_obj.is_expired():
                is_valid = verify_otp(secret_key, otp)
                print(is_valid)
                if not is_valid:
                    raise TokenError("Expired OTP")
            else:
                raise TokenError("Invalid OTP")
            user = User.objects.get(email=email)
            user.is_verified = True
            user.save()
            return super().validate(attrs)
        except Exception as e:
            raise TokenError(f"Invalid or Expired OTP: {e}")
