from flask import make_response, jsonify

#This class generates API Responses
class ApiMessage(dict):
    def __init__(self, status_code, message, json=None):
        self.http_code = status_code
        self.message = message
        self.json= json

    def __call__(self):
        json_response = jsonify({'message':self.message})
        if self.json is not None:
            return make_response(json_response, self.http_code, self.json)
        else:
            return json_response, self.http_code
 

CouldNotVerify = ApiMessage(401, 'Could not verify', {'WWW-Authenticate': 'Basic realm="Login required!"'})

CannotPerformThatAction = ApiMessage(403, 'Cannot perform that action!')

LoginRequired = ApiMessage(401, 'Login required')

UserDoesNotExist = ApiMessage(401, 'User does not exist')

UserAlreadyExists = ApiMessage(401, 'User already exists')

InvalidCredentials = ApiMessage(401, 'Invalid username or password')

TokenIsMissing = ApiMessage(401, 'Token is missing')

InvalidToken = ApiMessage(401, 'Token is invalid')

NoUsernameFound = ApiMessage(400, 'No username found!')

NoPasswordFound = ApiMessage(400, 'No password found!')

NoDataFound = ApiMessage(400, 'No data found!')

UsernameTooShort = ApiMessage(400, 'Username too short')

PasswordTooShort = ApiMessage(400, 'Password too short')

UserDeleted = ApiMessage(200, 'The user has been deleted')

UserPromoted = ApiMessage(200, 'The user has been promoted!')

UserCeated = ApiMessage(200, 'The user has been created!')

NoPromotionFound = ApiMessage(400, 'No promotion found')

NoValidPromotionFound = ApiMessage(400, 'No valid promotion found')

NoDivisionFound = ApiMessage(400, 'No division found')

NoJobNumberFound = ApiMessage(400, 'No job number found')

NoTextFound = ApiMessage(400, 'No text found')

TimesheetAlreadyExists = ApiMessage(400, 'Timesheet already exists')

TimesheetCeated = ApiMessage(200, 'The timesheet has been created!')
