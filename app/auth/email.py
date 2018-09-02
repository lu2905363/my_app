
from flask import render_template, current_app
from app.email import send_email


def send_password_reset_email(user):
    token = user.get_reset_password_token()
    send_email('[Microblog] Reset Your Password', sender=current_app.config['MAIL_USERNAME'],
               recipients=[user.email],
               text_body=render_template('email/reset_password.txt', user=user, token=token),
               html_body=render_template('email/reset_password.html', user=user, token=token)
               )


def send_registration_confirm_email(user):
    token = user.generate_confirmation_token()
    send_email('[Microblog] Confirm Your Registration', sender=current_app.config['MAIL_USERNAME'],
               recipients=[user.email],
               text_body=render_template('email/confirm_registration.txt', user=user, token=token),
               html_body=render_template('email/confirm_registration.html', user=user, token=token)
               )
