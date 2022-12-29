from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, Passwords, Actions
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
from sqlalchemy import func, text
from flask_mail import Message
from website.email import send_email

date = datetime.now()
auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'GET':
        return render_template('login.html'), 200
    # Pobierz adres ip z którego wysyłane jest żądanie
    # ip_address = request.remote_addr
    
    # Jeżeli żądanie ma flagę POST
    if request.method == 'POST':
        # Pobierz 'email' oraz 'password' z elementu form struktury HTML - email oraz hasło wprowadzone przez użytkownika
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if email and password:
            login_check = User.login_user(email, password)
            if login_check != False and login_check != True:
                return render_template('reset_email.html', user=login_check, token=login_check.get_reset_token())
            elif login_check == True:
                return redirect(url_for('views.home'))
            
        return render_template("login.html")

    return render_template("login.html")
        

@auth.route('/sign_up', methods=['GET', 'POST'])
def sign_up():

    if request.method == 'GET':
        return render_template('sign_up.html'), 200

    if request.method == 'POST':

        ip_address = request.remote_addr
        name = request.form.get('name')
        password = request.form.get('password')
        email = request.form.get('email')

        if name and password and email:
            user_created = User.create_user(name, password, email, ip_address)

            if user_created == True:
                flash('New account created.', category='success')
                return redirect(url_for('auth.login'))
            elif user_created == False:
                flash('User already exists', category='error')
                return render_template('sign_up.html'), 400
            else:
                return render_template('sign_up.html'), 400

        return render_template('sign_up.html'), 400


@auth.route('/logout')
@login_required
def logout():
    Actions.create_action('logout', 'Success', current_user.id)
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/password_reset', methods=['GET', 'POST'])
def reset():

    if request.method == 'GET':
        return render_template('reset.html')

    if request.method == 'POST':

        email = request.form.get('email')
        user = User.verify_email(email)
        if user:
            current_password = Passwords.query.filter_by(user_id=user.id).filter_by(expiration_date=None).first()
            time_delta = datetime.today() - timedelta(minutes=5)
            if current_password.creation_date > time_delta:
                flash('The password can be changed after 5 minutes from creation. You are not able to change the password right now.', category='error')
                Actions.create_action('password_reset', 'Failure', user.id)
                return redirect(url_for('auth.login'))
            else:
                send_email(user)

        return redirect(url_for('auth.login'))


@auth.route('/password_reset_verified/<token>', methods=['GET', 'POST'])
def reset_verified(token):

    user = User.verify_reset_token(token)
    if not user:
        return redirect(url_for('auth.login'))

    password = request.form.get('password')
    if password:
        password_validation = user.set_password(password)
        if password_validation == True:
            flash('Password changed.', category='success')
            return redirect(url_for('auth.login'))
        else:
            flash('Please try again.', category='error')
            return render_template('reset_verified.html')

    return render_template('reset_verified.html')