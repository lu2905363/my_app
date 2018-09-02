from datetime import datetime
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app import db
from app.auth import bp
from app.auth.forms import LoginForm, RegistrationForm, ResetPasswordForm, ResetPasswordRequestForm
from app.auth.email import send_registration_confirm_email, send_password_reset_email
from app.models import User


@bp.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        if not current_user.confirmed and request.blueprint != 'auth' and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))



@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('auth.login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    return render_template('auth/login.html', title='Sign In', form=form)


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        send_registration_confirm_email(user)
        flash('A confirmation email has been sent to your email address for verification.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', title='Register', form=form)


@bp.route('/resend_confirmation')
@login_required
def resend_confirmation():
    send_registration_confirm_email(current_user)
    flash('A new confirmation email has been sent to your email address for verification.')
    return redirect(url_for('main.index'))


@bp.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.verify_registration_token(token):
        flash('Congratulations! You have confirmed your registration and become a new user.')
        db.session.commit()
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@bp.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
            flash('Password-resetting mail has been sent. Check your inbox as soon as possible.')
        else:
            flash('Invalid email address. Try entering the email address of your logging account.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password_request.html', title='Reset your password', form=form)


@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        if user.check_password(form.password.data):
            flash('Please use a password different from your original one. '
                  'You can access the reset page from the link in your email within 10 minutes')
        else:
            user.set_password(form.password.data)
            db.session.commit()
            flash('You have successfully reset your password!')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)
