import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from flask import current_app

def send_email(to_email, subject, body, attachment_path=None):
    # Konfigurasi email dari environment variables
    EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
    EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
    EMAIL_USER = os.getenv("EMAIL_USER") or ""  # Tambahkan default empty string
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD") or ""  # Tambahkan default empty string
    EMAIL_FROM = os.getenv("EMAIL_FROM", EMAIL_USER or "")  # Tambahkan default empty string

    if not all([EMAIL_USER, EMAIL_PASSWORD]):
        current_app.logger.error("Email credentials not configured")
        return False

    try:
        # Membuat email message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM  # Pastikan ini string
        msg['To'] = to_email  # Pastikan ini string
        msg['Subject'] = subject  # Pastikan ini string
        
        # Tambahkan body email
        msg.attach(MIMEText(body, 'plain'))

        # Jika ada lampiran
        if attachment_path and os.path.isfile(attachment_path):
            with open(attachment_path, "rb") as f:
                part = MIMEApplication(
                    f.read(),
                    Name=os.path.basename(attachment_path)
                )  # Tutup kurung dengan benar
                
                # Set header untuk attachment
                part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                msg.attach(part)

        # Kirim email menggunakan SMTP
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)  # Pastikan keduanya string
            server.send_message(msg)
            
        current_app.logger.info(f"Email sent successfully to {to_email}")
        return True

    except Exception as e:
        current_app.logger.error(f"Failed to send email: {str(e)}")
        return False