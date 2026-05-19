from flask_mail import Message
from app import mail
from flask import current_app
import random
import string
from datetime import datetime, timedelta

def generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(email: str, otp: str, purpose: str = 'verification') -> bool:
    try:
        subject_map = {
            'verification': 'VaultX – Email Verification OTP',
            'login': 'VaultX – Login OTP Code',
            'reset': 'VaultX – Password Reset OTP'
        }
        
        subject = subject_map.get(purpose, 'VaultX – OTP Code')
        
        body = f"""
        <html>
        <body style="font-family: 'Courier New', monospace; background: #0a0a0f; color: #e0e0e0; padding: 40px;">
            <div style="max-width: 500px; margin: 0 auto; background: #12121f; border: 1px solid #00ff9f33; border-radius: 12px; padding: 40px;">
                <h1 style="color: #00ff9f; font-size: 28px; margin-bottom: 8px;">🔐 VaultX</h1>
                <p style="color: #888; font-size: 12px; margin-bottom: 30px;">AI-Powered Security Vault</p>
                <hr style="border: none; border-top: 1px solid #1e1e2e; margin: 20px 0;">
                <p style="color: #ccc;">Your one-time passcode:</p>
                <div style="background: #0a0a0f; border: 2px solid #00ff9f; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
                    <span style="font-size: 36px; font-weight: bold; letter-spacing: 12px; color: #00ff9f;">{otp}</span>
                </div>
                <p style="color: #888; font-size: 13px;">This code expires in {current_app.config.get('OTP_EXPIRY_MINUTES', 10)} minutes.</p>
                <p style="color: #666; font-size: 12px;">If you did not request this, ignore this email and secure your account.</p>
                <hr style="border: none; border-top: 1px solid #1e1e2e; margin: 20px 0;">
                <p style="color: #444; font-size: 11px;">VaultX Security System · Do not reply to this email</p>
            </div>
        </body>
        </html>
        """
        
        msg = Message(
            subject=subject,
            recipients=[email],
            html=body,
            sender=current_app.config.get('MAIL_DEFAULT_SENDER', 'noreply@vaultx.com')
        )
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f'Email send error: {e}')
        return False

def get_otp_expiry():
    minutes = current_app.config.get('OTP_EXPIRY_MINUTES', 10)
    return datetime.utcnow() + timedelta(minutes=minutes)
