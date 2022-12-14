from website import create_app
from flask_mail import Mail, Message
from flask import render_template, request, redirect, url_for, flash
import random
from website.models import User
from website.__init__ import db

app = create_app()

app.config['MAIL_SERVER']='smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '62263704a9884b'
app.config['MAIL_PASSWORD'] = 'ab1c0648f69bf0'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

@app.route('/remindPassword', methods=['GET', 'POST'])
def remindPassword():
    if request.method == 'POST':
        email = request.form.get('email')
        code = ''.join([str(random.randrange(0, 9, 1)) for _ in range(6)])
        user = User.query.filter_by(email=email).first()
        if user:
            user.remind_code = code
            db.session.commit()
            msg = Message('Hello from the other side!', sender =   'flask_authentication@mailtrap.io', recipients = [email])
            msg.body = "Hey here's your code: {0}".format(code)
            mail.send(msg)
            return redirect(url_for('auth.remindPasswordCheck'))
        else:
            flash('Email do not exist.', category='error')

    return render_template("password_remind.html")

if __name__ == '__main__':
    app.run(debug=True)