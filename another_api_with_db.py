from __future__ import division
from multiprocessing.dummy import Manager
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import api_messages

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
    public_id = db.Column(db.String(50), unique=True)
    division = db.Column(db.String(20))
    job_number = db.Column(db.String(10))
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return api_messages.TokenIsMissing()

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return api_messages.InvalidToken()

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/user', methods=['POST'])
@token_required
def create_users(current_user):

    if not current_user.admin:
        return api_messages.CannotPerformThatAction()
    if not current_user.active:
        return api_messages.CannotPerformThatAction()

    try:
        # Get data from request
        data = request.get_json()
        if not data.get("username"):
            return api_messages.NoUsernameFound()
        elif not data.get("password"):
            return api_messages.NoPasswordFound()
        elif (len(data.get("username")) <4) or (len(data.get("username")) >= 20):
            return api_messages.UsernameTooShort()
        elif len(data.get("password")) <5:
            return api_messages.PasswordTooShort()

    except:
        return api_messages.NoDataFound()

    # Query dabatase to see if the username already exists
    existing_user = User.query.filter_by(username=data["username"]).first()

    if not existing_user:
        hashed_password= generate_password_hash(data['password'], method='sha256')

        #Create new user
        new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, manager=False, admin=False, active=True)
        db.session.add(new_user)
        db.session.commit()

        return api_messages.UserCeated()
    else:
        return api_messages.UserAlreadyExists()

@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return api_messages.CannotPerformThatAction()
    if not current_user.active:
        return api_messages.CannotPerformThatAction()

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

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return api_messages.CannotPerformThatAction()
    if not current_user.active:
        return api_messages.CannotPerformThatAction()

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return api_messages.UserDoesNotExist()

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['password'] = user.password
    user_data['manager'] = user.manager
    user_data['admin'] = user.admin
    user_data['active'] = user.active

    return jsonify({'user': user_data})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return api_messages.CannotPerformThatAction()
    if not current_user.active:
        return api_messages.CannotPerformThatAction()

    #Get data from request
    try:
        data = request.get_json()
        if not data.get("promotion"):
            return api_messages.NoPromotionFound()
    except:
         return api_messages.NoDataFound()

    #Query database to see if user exists
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return api_messages.UserDoesNotExist()

    #Promote User 
    if data.get("promotion") == "admin":
        user.admin = True
    elif data.get("promotion") == "manager":
        user.manager = True
    elif data.get("promotion") == "inactive":
        user.active = False
    else:
        return api_messages.NoValidPromotionFound()
    db.session.commit()
    return api_messages.UserPromoted()

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return api_messages.CannotPerformThatAction()
    if not current_user.active:
        return api_messages.CannotPerformThatAction()

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return api_messages.UserDoesNotExist()

    db.session.delete(user)
    db.session.commit()

    return api_messages.UserDeleted()

@app.route('/login')
def login():
    auth = request.authorization

    # Authorization information does not exist
    if not auth or not auth.username or not auth.password:
        return api_messages.CouldNotVerify()

    user = User.query.filter_by(username=auth.username).first()
    ## Figure out what type user is
    print(user)

    # User does not exist
    if not user:
        return api_messages.UserDoesNotExist()

    # Check if the password matches
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token': token})

    # Password does not exist or is invalid
    return api_messages.InvalidCredentials()

@app.route('/timesheet', methods=['POST'])
@token_required
def create_timesheet(current_user):
    try:
        data = request.get_json()
        if not data.get("division"):
            return api_messages.NoDivisionFound()
        elif not data.get("job_number"):
            return api_messages.NoJobNumberFound()
        elif not data.get("text"):
            return api_messages.NoTextFound()
    except:
        return api_messages.NoDataFound()

    # Query dabatase to see if the timesheet already exists
    existing_timesheet = Timesheet.query.filter_by(job_number=data["job_number"]).first()

    if not existing_timesheet:

        #Create new user
        new_timesheet = Timesheet(public_id=str(uuid.uuid4()), division=data["division"], job_number=data["job_number"] , text=data["text"], complete=False, user_id=current_user.username)
        db.session.add(new_timesheet)
        db.session.commit()

        return api_messages.TimesheetCeated()
    else:
        return api_messages.TimesheetAlreadyExists()

@app.route('/timesheets', methods=['GET'])
@token_required
def get_all_timesheets(current_user):

    timesheets = Timesheet.query.all()

    output = []

    for timesheet in timesheets:
        timesheet_data = {}
        timesheet_data['public_id'] = timesheet.public_id
        timesheet_data['division'] = timesheet.division
        timesheet_data['job_number'] = timesheet.text
        timesheet_data['text'] = timesheet.text
        timesheet_data['complete'] = timesheet.complete
        timesheet_data['user_id'] = timesheet.user_id
        output.append(timesheet_data)

    return jsonify({"timesheets": output})

if __name__ == '__main__':
    # app.run(debug=True)
    app.run(debug=True, host="0.0.0.0")