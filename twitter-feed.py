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
app.config['SECRET_KEY'] = 'vnkdjnfjknfl1232#'
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


var socket;

$(document).ready(function() {
#var socket = io.connect('http://localhost:5000/');
var socket = io.connect('http://' + document.domain + ':' + location.port);

socket.on('connect', function() {
  alert('test');
  socket.emit('my event', {data: 'I\'m connected!'});
  console.log('User has been connected!');
});

socket.on('message', function(msg) {
  alert('received')
  $('#messages').append("<li>"+msg+"</li>")
});

});

$('#sendButton').on("click", function() {

var myMessage = $('#myMessage').val()
socket.send(myMessage)
alert('sent!')
});
