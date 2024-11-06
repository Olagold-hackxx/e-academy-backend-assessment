import pyotp
import base64
import os

# Generate a unique secret key for each user
def generate_otp_secret():
    return base64.b32encode(os.urandom(10)).decode('utf-8')

# Generate a TOTP code based on the secret key
def generate_otp(secret_key: str, interval: int = 500) -> str:
    totp = pyotp.TOTP(secret_key, digits=6, interval=interval)
    return totp.now()

# Verify the OTP code entered by the user
def verify_otp(secret_key: str, otp_code: str, interval: int = 500) -> bool:
    totp = pyotp.TOTP(secret_key, digits=6, interval=interval)
    return totp.verify(otp_code)
