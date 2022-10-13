import re
import smtplib
from email.message import EmailMessage
from password_strength import PasswordPolicy
from validate_email import validate_email

user_regex = "^[a-zA-Z0-9_.-]+$"
password_feedback = 'Password should contain at least an uppercase letter, a number and an special character with 10 characters long.'

F_ACTIVE = 'ACTIVE'
F_INACTIVE = 'INACTIVE'
U_UNCONFIRMED = 'UNCONFIRMED'
U_CONFIRMED = 'CONFIRMED'
EMAIL_APP = 'EMAIL_APP'

policy = PasswordPolicy.from_names(
    length=10,
    uppercase=1,
    numbers=1,
    special=1,
)


def is_email_valid(email):
    return validate_email(email)


def is_username_valid(user):
    if re.search(user_regex, user):
        return True
    else:
        return False


def is_password_valid(password):
    return len(policy.password(password).test()) == 0


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()
