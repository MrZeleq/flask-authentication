from flask import Blueprint, render_template
from flask_login import login_required, current_user
from .models import User, Actions

views = Blueprint('views', __name__)


@views.route('/')
def mainPage():
    return render_template("base.html")

@views.route('/home')
@login_required
def home():
    users = User.query.filter(User.id == current_user.id).first()
    actions_list = [[action.action_id, action.user_id, action.action_name, action.action_date, action.status] for action in Actions.query.filter(Actions.user_id == current_user.id).all()]
    return render_template("home.html", user=current_user, users=users, actions_list=actions_list)


