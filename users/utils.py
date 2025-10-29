# users/utils.py
import logging
import os
from django.conf import settings
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from python_http_client.exceptions import HTTPError, ForbiddenError

logger = logging.getLogger(__name__)

class SendEmailError(RuntimeError):
    """Raised when SendGrid fails to send."""
    pass

def send_reset_email(to_email: str, subject: str, html_content: str, plain_text: str = None):
    """
    Send an email via SendGrid API.
    Will raise SendEmailError on failure. Logs detailed info for devs.
    """
    api_key = getattr(settings, "SENDGRID_API_KEY", None) or os.getenv("SENDGRID_API_KEY")
    sender = getattr(settings, "SENDGRID_SENDER", None) or os.getenv("SENDGRID_SENDER")
    sender_name = getattr(settings, "SENDGRID_SENDER_NAME", None) or os.getenv("SENDGRID_SENDER_NAME", "")

    if not api_key:
        logger.error("SENDGRID_API_KEY not configured")
        raise SendEmailError("Email provider not configured")

    if not sender:
        logger.error("SENDGRID_SENDER not configured")
        raise SendEmailError("Sender address not configured")

    from_email = Email(email=sender, name=sender_name)  # structured from
    to = To(to_email)

    message = Mail(
        from_email=from_email,
        to_emails=to,
        subject=subject,
        html_content=html_content
    )
    if plain_text:
        message.add_content(Content("text/plain", plain_text))

    client = SendGridAPIClient(api_key)
    try:
        response = client.send(message)
        status = getattr(response, "status_code", None)
        body = getattr(response, "body", None)
        logger.info("SendGrid response status=%s body=%s", status, body)
        # SendGrid usually returns 202 for accepted
        if status and int(status) in (200, 201, 202):
            return True
        logger.warning("Unexpected SendGrid status: %s", status)
        return False
    except ForbiddenError as fe:
        logger.exception("SendGrid ForbiddenError status=%s body=%s", getattr(fe, "status_code", None), getattr(fe, "body", None))
        raise SendEmailError("SendGrid forbidden: check sender identity and API key permissions") from fe
    except HTTPError as he:
        logger.exception("SendGrid HTTPError status=%s body=%s", getattr(he, "status_code", None), getattr(he, "body", None))
        raise SendEmailError("SendGrid HTTPError") from he
    except Exception as exc:
        logger.exception("Unexpected error sending email: %s", exc)
        raise SendEmailError("Unexpected error sending email") from exc
