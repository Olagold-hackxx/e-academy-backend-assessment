from django.test import TestCase
from django.utils import timezone
from unittest.mock import patch, MagicMock
from datetime import timedelta
from account.models import User, OneTimePassword
from account.serializers import (
    UserRegisterSerializer, LoginUserSerializer, PasswordResetSerializer, VerifyOTPSerializer
)
from rest_framework.exceptions import AuthenticationFailed, ValidationError


class UserRegisterSerializerTest(TestCase):

    @patch("account.serializers.generate_otp_secret", return_value="mocksecret")
    @patch("account.serializers.generate_otp", return_value="123456")
    @patch("account.serializers.send_verification_email.delay")
    def test_user_register(self, mock_send_verification_email, mock_generate_otp, mock_generate_otp_secret):
        data = {
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "password": "password123",
            "confirm_password": "password123"
        }
        serializer = UserRegisterSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()

        # Ensure user and OTP are created correctly
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(OneTimePassword.objects.count(), 1)
        otp_instance = OneTimePassword.objects.first()
        self.assertEqual(otp_instance.user, user)
        self.assertEqual(otp_instance.decrypt_code(
            otp_instance.code), "123456")
        mock_send_verification_email.assert_called_once()


class LoginUserSerializerTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com", password="password123", first_name="test", last_name="unittest", is_verified=True)

    @patch("account.serializers.authenticate")
    def test_login_user(self, mock_authenticate):
        # Mock the authenticate function to return the user instance
        mock_authenticate.return_value = self.user

        data = {
            "email": "test@example.com",
            "password": "password123"
        }
        serializer = LoginUserSerializer(
            data=data, context={"request": MagicMock()})
        self.assertTrue(serializer.is_valid())
        result = serializer.validated_data

        # Verify response tokens
        self.assertIn("user", result)
        self.assertEqual(result["user"].email, "test@example.com")

    def test_login_invalid_credentials(self):
        data = {
            "email": "wrong@example.com",
            "password": "wrongpassword"
        }
        serializer = LoginUserSerializer(
            data=data, context={"request": MagicMock()})
        with self.assertRaises(AuthenticationFailed):
            serializer.is_valid(raise_exception=True)


class PasswordResetSerializerTest(TestCase):

    @patch("account.serializers.send_verification_email.delay")
    def test_password_reset_valid_email(self, mock_send_verification_email):
        User.objects.create_user(
            email="test@example.com", password="password123", first_name="test", last_name="unittest")
        data = {"email": "test@example.com"}
        serializer = PasswordResetSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        serializer.validate(data)
        mock_send_verification_email.assert_called()


class VerifyOTPSerializerTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com", password="password123", first_name="test", last_name="unittest")
        self.otp_instance = OneTimePassword.objects.create(
            user=self.user,
            code="123456",
            secret_key="mocksecret",
            expires_at=timezone.now() + timedelta(minutes=5)
        )
        self.otp_instance.code = self.otp_instance.encrypt_code("123456")
        self.otp_instance.save()

    @patch("account.serializers.verify_otp", return_value=True)
    def test_verify_otp_valid(self, mock_verify_otp):
        data = {
            "email": "test@example.com",
            "otp": "123456"
        }
        serializer = VerifyOTPSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        serializer.validate(data)

        # Confirm user is verified
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_verified)

    @patch("account.serializers.verify_otp", return_value=False)
    def test_verify_otp_invalid(self, mock_verify_otp):
        data = {
            "email": "test@example.com",
            "otp": "wrongotp"
        }
        serializer = VerifyOTPSerializer(data=data)
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)
