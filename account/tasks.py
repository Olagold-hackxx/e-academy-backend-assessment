from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def send_verification_email(self, email, subject, message):
    """
    Celery task to send a verification email with exponential backoff for retries.
    Logs success and error messages for monitoring.
    """
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        logger.info(f'Verification email successfully sent to {email}')
    except Exception as exc:
        logger.error(f'Failed to send verification email to {email}: {exc}')
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=2 ** self.request.retries)
