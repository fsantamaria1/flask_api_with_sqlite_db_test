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
    username = db.Column(db.String(20))
    password = db.Column(db.String(65))
    manager = db.Column(db.Boolean)
    admin = db.Column(db.Boolean)
    active = db.Column(db.Boolean)

class Timesheet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    division = db.Column(db.String(20))
    job_number = db.Column(db.String(10))
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

@app.route('/user', methods=['POST'])
def create_users():

    try:
        # Get data from request
        data = request.get_json()
        # if not data["username"]:
        if not data.get("username"):
            return jsonify({'message': 'No username found!'}), 400
        elif not data.get("password"):
            return jsonify({'message': 'No password found!'}), 400
        elif (len(data.get("username")) <4) or (len(data.get("username")) >= 20):
            return jsonify({'message': 'Username too short!'}), 400
        elif len(data.get("password")) <5:
            return jsonify({'message': 'Password too short!'}), 400

    except:
        return jsonify({'message': 'No data found!'}), 400

    # Query dabatase to see if the username already exists
    existing_user = User.query.filter_by(username=data["username"]).first()

    if not existing_user:
        hashed_password= generate_password_hash(data['password'], method='sha256')

        #Create new user
        new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, manager=False, admin=False, active=False)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'New user created!'})
    else:
        return jsonify({"message": "User already exists!"})

@app.route('/users', methods=['GET'])
def get_all_users():

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['manager'] = user.manager
        user_data['admin'] = user.admin
        user_data['active'] = user.active
        output.append(user_data)
    return jsonify({'users': output})

@app.route('/login')
def login():
    auth = request.authorization

    # Authorization information does not exist
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    # User does not exist
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token': token})

    # Password does not exist
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

if __name__ == '__main__':
    app.run(debug=True)