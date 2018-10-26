
from flask import Flask, render_template, session, request, jsonify
from flask_login import LoginManager, UserMixin
from flask_session import Session
from flask import redirect, flash
from flask_socketio import SocketIO

from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
import validators


from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy import MetaData
from sqlalchemy import Table
from flask_wtf import FlaskForm

from flask_login import logout_user
from flask_login import current_user, login_user

import os
import sqlite3
import re

project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(os.path.join(project_dir, "user_message_11.db"))

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = '123445667'
app.config["SQLALCHEMY_DATABASE_URI"] = database_file

socketio = SocketIO(app)

db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = password
        #generate_password_hash(password)

    def check_password(self, password):
        print(self.password_hash)
        print(password)
        if (self.password_hash == password):
            return(True)
        return(False)
        #return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)


class UserMessage(db.Model):

    index = db.Column(db.Integer, nullable= False, primary_key=True)
    user = db.Column(db.String(80), nullable=False)
    message = db.Column(db.String(80), nullable=False)

    def __init__(self, user, message):
        self.user = user
        self.message = message
        super(UserMessage,self).__init__()

    def __repr__(self):
        return "<User: {}, Message: {}>".format(self.user, self.message)


class Links(db.Model):
    index = db.Column(db.Integer, nullable= False, primary_key=True)
    link = db.Column(db.String(100), nullable = False)
    def __init__(self, link):
        self.link = link
        super(Links,self).__init__()

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

@app.route('/user_<name>')
def userPage(name):
    user_messages = UserMessage.query.filter_by(user=name).all()
    return(render_template('message-page.html', messages = user_messages, name = name))


@app.route('/logout')
def logout():
    logout_user()
    return render_template('homepage.html', current_user = current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if (current_user.is_authenticated):
        print('is authenticated')
        return(redirect('/'))
    form = LoginForm()
    if (form.validate_on_submit()):
        print(form.username.data)
        user = User.query.filter_by(username=form.username.data).first()
        print('user value:')
        print(user)
        if (user is None or not user.check_password(form.password.data)):
            flash('Invalid username or password')
            print('didnt match')
            return(redirect('/login'))
        user.authenticated = True
        db.session.add(user)
        db.session.commit()
        print('authenticated?')
        login_user(user, remember=True)
        print('logged in')
        print('matched')
        return(redirect('/'))
    return(render_template('login.html', title='Sign In', form=form))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect('/login')
    return render_template('register.html', title='Register', form=form)

@app.route('/')
def sessions():
    return render_template('homepage.html', current_user = current_user, history = UserMessage.query.all(), links = Links.query.all())

def messageReceived(methods=['GET', 'POST']):
    print('message was received!!!')

@app.route('/message_<index>')
def movieProfile(message):
    item = UserMessage.query.get(message)

    #need to repopulate databse with correct Path
    link = 'static/' + movie_actor_map[title][1]
    return render_template('message-page.html', user = item.username, message = item.message)

@socketio.on('my event')
def handle_my_custom_event(json, methods=['GET', 'POST']):

    print('received my event: ' + str(json))
    #add log to the database
    print(current_user.username)
    #print(json['message'])
    print(json)

    if ('message' in json):
        #check if message is a link
        #if so, add the link to link database
        #url = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+] |[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', json['message'])
        if ('www' in json['message']):
            print('in here')
            link_entry = Links(link=json['message'])
            db.session.add(link_entry)
            db.session.commit()
        print('out of if statement')

        #if (json['message'][0:3] == 'www'):
        #db.session.add(url)
        #    db.session.commit()
        user_message = UserMessage(user=current_user.username, message=json['message'])
        db.session.add(user_message)
        db.session.commit()

    socketio.emit('my response', json, callback=messageReceived, broadcast = True)


def create_connection(db_file):
    """ create a database connection to a SQLite database """
    global conn
    try:
        conn = sqlite3.connect(db_file)
        conn.close()
    except Error as e:
        print(e)

if __name__ == '__main__':
    create_connection("C:\\sqlite\db\user_message_11.db")
    db.create_all()
    socketio.run(app, debug=True)
