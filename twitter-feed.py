import os

from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask_socketio import SocketIO, send

from sqlalchemy import create_engine
from sqlalchemy import MetaData
from sqlalchemy import Table

from flask_sqlalchemy import SQLAlchemy
import sqlite3


app = Flask(__name__)
socketio = SocketIO(app)

@socketio.on('message')
def handleMessage(msg):
    console.log('received message')
    send(msg, broadcast = True)


@app.route('/',  methods=["GET", "POST"])
def landingPage():
    return(render_template('homepage.html'))


if __name__ == "__main__":
    #create_connection("C:\\sqlite\db\final_1.db")
    #db.create_all()
    #socketio.run(app)
    app.run(debug=True)
