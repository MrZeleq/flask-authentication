import regex as re
from . import db
import os
import jwt
from time import time
from werkzeug.security import generate_password_hash, check_password_hash
import flask_login
from sqlalchemy import ForeignKey, DateTime, func
from datetime import datetime, timedelta
from flask import flash

class User(db.Model, flask_login.UserMixin):
    __tablename__= 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    ip = db.Column(db.String(150))
    register_date = db.Column(DateTime, unique=True)
    
    def __repr__(self):
        return 'User {}'.format(self.name)
    
    def set_password(self, password):
        password_validation = self.password_check(password)
        if password_validation["password_ok"]:
            time_delta = datetime.today() - timedelta(days=30)
            passwords_history = Passwords.query.filter(Passwords.user_id == self.id).filter(Passwords.expiration_date != None).filter(Passwords.expiration_date > time_delta).all()
            if len(passwords_history):
                for i in range(len(passwords_history)):
                    if check_password_hash(passwords_history[i].password, password):
                        flash('The password you entered expired ' + str(passwords_history[i].expiration_date.date()) + \
                            " and cannot be reused in the period of month from expiration date", category='error')
                        return False
            expiration_query = Passwords.query.filter(Passwords.user_id == self.id).filter(Passwords.expiration_date == None)
            if expiration_query.first():
                expiration_query.update({'expiration_date': datetime.now()})
                db.session.commit()
            passwords = Passwords()
            passwords.password = generate_password_hash(password)
            passwords.user_id = self.id
            passwords.creation_date = datetime.now()

            db.session.add(passwords)
            db.session.commit()

            Actions.create_action('create_password', 'Success', self.id)
            return True
        else:
            # Passwords.query.filter_by(password=passwords.password).delete()
            # db.session.commit()
            if password_validation["length_error"]:
                flash('Password must be at least 8 characters.', category='error')
            elif password_validation["digit_error"]:
                flash('Password must have at least 1 digit or more', category='error')
            elif password_validation["uppercase_error"]:
                flash('Password must have at least 1 uppercase letter or more', category='error')
            elif password_validation["lowercase_error"]:
                flash('Password must have at least 1 lowercase letter or more', category='error')
            elif password_validation["symbol_error"]:
                flash('Password must have at least 1 special symbol or more: !#$%&', category='error')

            Actions.create_action('create_password', 'Failure', self.id)
            return password_validation
    
    def verify_password(self, password):
        current_password = Passwords.query.filter_by(user_id=self.id).filter_by(expiration_date=None).first()
        time_delta = datetime.today() - timedelta(minutes=20)
        if current_password.creation_date < time_delta:
            return "expired"
        else:
            return check_password_hash(current_password.password, password)
    
    def get_reset_token(self, expires=500):
        return jwt.encode({'reset_password': self.name, 'exp': time() + expires},
                           "secret", algorithm="HS256")
    
    @staticmethod
    def password_check(password):
        """
        Verify the strength of 'password'
        Returns a dict indicating the wrong criteria
        A password is considered strong if:
            8 characters length or more
            1 digit or more
            1 symbol or more
            1 uppercase letter or more
            1 lowercase letter or more
        """

        # calculating the length
        length_error = len(password) < 8

        # searching for digits
        digit_error = re.search(r"\d", password) is None

        # searching for uppercase
        uppercase_error = re.search(r"[A-Z]", password) is None

        # searching for lowercase
        lowercase_error = re.search(r"[a-z]", password) is None

        # searching for symbols
        symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

        # overall result
        password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

        return {
            'password_ok' : password_ok,
            'length_error' : length_error,
            'digit_error' : digit_error,
            'uppercase_error' : uppercase_error,
            'lowercase_error' : lowercase_error,
            'symbol_error' : symbol_error,
        }
    
    @staticmethod
    def verify_reset_token(token):
        try:
            name = jwt.decode(token, "secret", algorithms="HS256")['reset_password']
        except Exception as e:
            print(e)
            return
        return User.query.filter_by(name=name).first()
    
    @staticmethod
    def create_user(name, password, email, ip_address):

        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            return False
        
        user = User()

        user.name = name
        user.email = email
        user.ip = ip_address
        user.register_date = datetime.now()

        db.session.add(user)
        db.session.commit()

        password_validation = user.set_password(password)
        if password_validation == True:
            Actions.create_action('register', 'Success', user.id)
            return True
        else:
            Actions.query.filter_by(user_id=user.id).delete()
            User.query.filter_by(id=user.id).delete()
            db.session.commit()
            Actions.create_action('register', 'Failure')
            return password_validation
    
    @staticmethod
    def login_user(email, password):

        user = User.query.filter_by(email=email).first()

        if user:
            current_password = user.verify_password(password)
            if current_password and current_password != "expired":
                time_delta = datetime.today() - timedelta(hours=0, minutes=5)
                if len(Actions.query.filter(Actions.user_id == user.id).filter(Actions.action_name == 'login').\
                    filter(Actions.status == 'Failure').filter(Actions.action_date > time_delta).all()) >= 3:
                    flash('Too much login attemptions, please try again after 5 minutes.', category='error')
                    Actions.create_action('login', 'Failure', user.id)
                    return False
                else:
                    Actions.create_action('login', 'Success', user.id)
                    flask_login.login_user(user, remember=True)
                    return True
            elif current_password == "expired":
                flash('The password expires after 10 minutes. Please change your password.', category='error')
                Actions.create_action('login', 'Failure', user.id)
                return user
            else:
                flash('Password incorrect', category='error')
                Actions.create_action('login', 'Failure', user.id)
                return False
        else:
            flash('User do not exist', category='error')
            Actions.create_action('login', 'Failure')
        
        return False
    
    @staticmethod
    def verify_email(email):

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not found.', category='error')
        return user

class Actions(db.Model, flask_login.UserMixin):
    __tablename__= 'actions'
    action_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'))
    action_name = db.Column(db.String(150))
    action_date = db.Column(DateTime, unique=True)
    status = db.Column(db.String(150))
    
    def __repr__(self):
        return 'Action {}'.format(self.action_id)
    
    @staticmethod
    def create_action(action_name, status, user_id=False):
        if user_id:
            action = Actions()
            action.user_id = user_id
            action.action_name = action_name
            action.action_date = datetime.now()
            action.status = status
            db.session.add(action)
            db.session.commit()
        else:
            action = Actions()
            action.action_name = action_name
            action.action_date = datetime.now()
            action.status = status
            db.session.add(action)
            db.session.commit()



class Passwords(db.Model, flask_login.UserMixin):
    __tablename__= 'passwords'
    password = db.Column(db.String(150), primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id', ondelete="CASCADE"))
    creation_date = db.Column(DateTime, unique=True)
    expiration_date = db.Column(DateTime)

    def __repr__(self):
        return 'Password {}'.format(self.password)