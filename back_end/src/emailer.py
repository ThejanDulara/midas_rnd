import smtplib
from email.mime.text import MIMEText
from flask import current_app as app

def send_mail(to_email, subject, html_body):
    msg = MIMEText(html_body, "html")
    msg["Subject"] = subject
    msg["From"] = app.config["SMTP_USER"]
    msg["To"] = to_email

    with smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"]) as s:
        s.starttls()
        s.login(app.config["SMTP_USER"], app.config["SMTP_PASS"])
        s.send_message(msg)
