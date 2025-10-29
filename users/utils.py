# users/utils.py
import os
from django.conf import settings
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

def send_reset_email(to_email: str, subject: str, html_content: str, plain_text: str = None):
    """
    Send an email using SendGrid. Raises exceptions on failure.
    """
    api_key = getattr(settings, "SENDGRID_API_KEY", None) or os.getenv("SENDGRID_API_KEY")
    if not api_key:
        raise RuntimeError("SENDGRID_API_KEY not configured")

    message = Mail(
        from_email=getattr(settings, "SENDGRID_SENDER", "noreply@example.com"),
        to_emails=to_email,
        subject=subject,
        html_content=html_content,
    )

    # Optionally include plain text
    if plain_text:
        message.add_content({"type": "text/plain", "value": plain_text})

    client = SendGridAPIClient(api_key)
    response = client.send(message)
    # you may want to check response.status_code in production
    return response
