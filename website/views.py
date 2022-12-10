from flask import Blueprint, render_template
from flask_login import login_required, current_user

views = Blueprint('views', __name__)


@views.route('/')
def mainPage():
    return render_template("base.html")

@views.route('/home')
@login_required
def home():
    return render_template("home.html", user=current_user)

