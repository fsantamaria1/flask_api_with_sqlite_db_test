from __future__ import division
from multiprocessing.dummy import Manager
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\fsantamaria\\OneDrive - Berry-It\\Documents\\VS Code Files\\timesheets.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))
    manager = db.Column(db.Boolean)
    admin = db.Column(db.Boolean)


class Timesheet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    division = db.Column(db.String(20))
    job_number = db.Column(db.String(10))
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


if __name__ == '__main__':
    app.run(debug=True)