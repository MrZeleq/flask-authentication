from flask import Blueprint, render_template
from flask_login import login_required, current_user
from .models import User

views = Blueprint('views', __name__)


@views.route('/')
def mainPage():
    return render_template("base.html")

@views.route('/home')
@login_required
def home():
    users = User.query.all()
    return render_template("home.html", user=current_user, users=users)


