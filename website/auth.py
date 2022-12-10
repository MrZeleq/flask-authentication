from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from datetime import datetime
from sqlalchemy import func, text

date = datetime.now()
auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    ip_address = request.remote_addr
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        

        user = User.query.filter_by(email=email).first()
        date = datetime.now()
        calc_date = date - user.failed_login_time
        if calc_date.total_seconds() > 15 and user.failed_login_attempts >=3:
            user.failed_login_attempts = 0
            db.session.commit()
        if user:
            if user.failed_login_attempts >= 3:
                flash('To many attempts.', category='error')
                #flash(calc_date)

            if check_password_hash(user.password, password) and ip_address==user.ip and user.failed_login_attempts <= 3:
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))

            if check_password_hash(user.password, password) == False:
                flash('Incorrect password, try again.', category='error')
                user.failed_login_time = date
                user.failed_login_attempts += 1
                db.session.commit()
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    ip_address = request.remote_addr
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

            
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, name=name, password=generate_password_hash(
                password1, method='sha256'), ip=ip_address, failed_login_attempts=0,failed_login_time=date)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)


    date = datetime.now()