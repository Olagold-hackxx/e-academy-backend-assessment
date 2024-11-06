from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.validators import EmailValidator
from django.utils import timezone
from .manager import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=100, verbose_name=_("First Name"))
    last_name = models.CharField(max_length=100, verbose_name=_("Last Name"))
    email = models.EmailField(
        max_length=255, unique=True, verbose_name=_("Email Address"), validators=[EmailValidator()]
    )
    is_verified = models.BooleanField(default=False)
    is_staff= models.BooleanField(default=False)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]
    objects = UserManager()

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {"refresh": str(refresh), "access": str(refresh.access_token)}


class OneTimePassword(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    code = models.CharField(max_length=128)
    secret_key = models.CharField(max_length=512)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"OTP for {self.user.email}: {self.code}"

    def encrypt_code(self, code):
        f = Fernet(settings.FERNET_KEY)
        encrypted_code = f.encrypt(code.encode())
        return encrypted_code.decode()

    def decrypt_code(self, encrypted_code):
        f = Fernet(settings.FERNET_KEY)
        decrypted_code = f.decrypt(encrypted_code.encode())
        return decrypted_code.decode()

    def is_expired(self):
        return timezone.now() > self.expires_at
