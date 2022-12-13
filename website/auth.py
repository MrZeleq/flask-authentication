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
    # Pobierz adres ip z którego wysyłane jest żądanie
    ip_address = request.remote_addr
    
    # Jeżeli żądanie ma flagę POST
    if request.method == 'POST':
        # Pobierz 'email' oraz 'password' z elementu form struktury HTML - email oraz hasło wprowadzone przez użytkownika
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Wykonaj zapytanie o użytkownika z emailem podanym wcześniej w elemencie form, first jest użyte prewencyjnie,
        # gdyby zdarzył się duplikat w tabeli.
        user = User.query.filter_by(email=email).first()

        # Pobierz obecną datę oraz czas logowania
        date = datetime.now()
        # Oblicz różnicę pomiędzy czasem próby logowania a ostatnim czasem niepoprawnego logowania
        calc_date = date - user.failed_login_time
        # Jeżeli od ostatniego niepoprawnego logowania upłynęło więcej niż 15 sekund oraz użytkownik próbował się zalogować więcej niż lub 3 razy
        # to wyzeruj liczbę niepoprawnych logowań oraz zaaktualizuj bazę danych.
        # Ma to na celu zasymulowanie akcji monitorującej podejrzane zachowanie.
        if calc_date.total_seconds() > 15 and user.failed_login_attempts >=3:
            user.failed_login_attempts = 0
            db.session.commit()
        
        # Jeżeli użytkownik o podanym mailu istnieje
        if user:
            # Jeżeli wystąpiły więcej niż 3 nieudane próby to poinformuj użytkownika o błędzie
            if user.failed_login_attempts >= 3:
                flash('To many attempts.', category='error')
                #flash(calc_date)

            # Jeżeli adres ip żądania oraz adres ip konta nie zgadzają się to poinformuj o błędzie
            # oraz zaakutalizuj bazę danych
            if ip_address != user.ip:
                flash('Current IP address not matching to signed IP address!', category='error')
                user.failed_login_time = date
                user.failed_login_attempts += 1
                db.session.commit()

            # Jeżeli hasło wprowadzone przez użytkownika jest takie samo jak to istniejące w bazie danych oraz
            # adres ip żądania jest takie samo jak adres ip użytkownika oraz
            # nieduanych prób logowania jest mniej lub równe 3 
            # to poinformuj użytkownika o udanym logowaniu, zaloguj użytkownika (zapamiętaj w przeglądarce) oraz
            # przekieruj na stronę home
            if check_password_hash(user.password, password) and ip_address==user.ip and user.failed_login_attempts <= 3:
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))

            # Jeżeli hasło się nie zgadza to poinformuj o błędzie oraz
            # przypisz aktualną datę i czas nieudanej próby logowania oraz dodaj jeden
            # do licznika nieudanych prób logowania, zaaktualizuj bazę danych
            if check_password_hash(user.password, password) == False:
                flash('Incorrect password, try again.', category='error')
                user.failed_login_time = date
                user.failed_login_attempts += 1
                db.session.commit()
        # W przeciwnym wypadku poinformuj użytkownika, że email nie istnieje w bazie danych
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
    # Pobierz adres ip z którego wysyłane jest żądanie
    ip_address = request.remote_addr

    # Jeżeli żądanie ma flagę POST
    if request.method == 'POST':
        # Pobierz 'email', 'firstName' oraz 'password1' i 'password2' z elementu form struktury HTML
        email = request.form.get('email')
        name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # Wyszukaj użytkownika    
        user = User.query.filter_by(email=email).first()
        # Jeśli użytkownik istnieje poinformuj o błędzie
        if user:
            flash('Email already exists.', category='error')
        # Email musi składać się przynajmniej z 4 znaków
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        # Nazwa użytkownika musi składać się z przynajmniej 2 znaków
        elif len(name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        # Użytkownik musi wprowadzić dwa razy identyczne hasło
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        # Hasło musi składać się z przynajmniej 7 znaków
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        # W przeciwnym wypadku (pozytywnym)
        else:
            # Stwórz nowy rekord w tabeli User
            new_user = User(email=email, name=name, password=generate_password_hash(
                password1, method='sha256'), ip=ip_address, failed_login_attempts=0,failed_login_time=date)
            # Zaaktualizuj bazę danych
            db.session.add(new_user)
            db.session.commit()
            # Zaloguj użytkownika
            login_user(new_user, remember=True)
            # Poinformuj o udanym procesie tworzenia konta
            flash('Account created!', category='success')
            # Przekieruj na stronę /home
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)