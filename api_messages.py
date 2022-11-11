from flask import make_response, jsonify

#This class generates API Responses
class ApiMessage(dict):
    def __init__(self, status_code, message, json=None):
        self.code = status_code
        self.message = message
        self.json= json

    def __call__(self):
        json_response = jsonify({'message':self.message})
        if self.json is not None:
            return make_response(json_response, self.code, self.json)
            # return make_response(jsonify({'message': self.message}), self.code, self.json)
        else:
            return json_response, self.code
            # return jsonify({"message":self.message}), self.code
 

CouldNotVerify = ApiMessage(401, 'Could not verify', {'WWW-Authenticate': 'Basic realm="Login required!"'})

CannotPerformThatAction = ApiMessage(403, 'Cannot perform that action!')

LoginRequired = ApiMessage(401, 'Login required')

UserDoesNotExist = ApiMessage(401, 'User does not exist')

InvalidCredentials = ApiMessage(401, 'Invalid username or password')
