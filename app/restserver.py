from app import app
from flask.ext.restful import Api, Resource, reqparse, fields, marshal
import json
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from flask.ext.httpauth import HTTPBasicAuth
import logging
from flask import request, jsonify

api = Api(app)
auth = HTTPBasicAuth()




class Utility:
    @staticmethod
    def generate_auth_token(user, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': user['Username']})
    
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            logging.warning('decoding')
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        id = data['id']
        return id


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    if (not ('authorization' in request.headers)):
        logging.warning("nothing in token")
        return False
    username_or_token = request.headers['authorization']
    logging.warning("verifying: " + username_or_token)
    
    user = Utility.verify_auth_token(username_or_token)
    #if not user:
        # try to authenticate with username/password
    if not user:
        logging.warning('verification failed')
        return False
    logging.warning('verification succeeded')
    return True


class PasswordRecoveryAPI(Resource):

    def __init__(self):
        self.reqparse = reqparse.RequestParser() #Basic mail format has been checked
        self.reqparse.add_argument('Email', type=str, required=True,
                               help='Email required',
                               location='json')
    
        super(PasswordRecoveryAPI, self).__init__()

    

    def post(self):
        args = self.reqparse.parse_args()
#check with the database
        success = True
        
        return {'success': success}, 201
    

class IdeaAPI(Resource):

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('Query', type=str, required=True,
                               help='Query required',
                               location='json')
    
        super(IdeaAPI, self).__init__()

    
    @auth.login_required
    def get(self):
        with open('data2.json') as data_file:    
            data = json.load(data_file)
        #logging.warning(request.authentication)
        return data


    def post(self):
        args = self.reqparse.parse_args()
        
        logging.warning(args)
        return {'Result': 0}, 201


class QueryAPI(Resource):
    decorators = [auth.login_required]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()

        super(QueryAPI, self).__init__()


    def get(self, queries):
        queryID = app.config["CURRENT_QUERY"]
        if app.config["CURRENT_QUERY"] == app.config["MAX_QUERY"] :
            app.config["CURRENT_QUERY"] = 0
        else:
            app.config["CURRENT_QUERY"] +=1

        
        return {"QueryID" : queryID}



class QueryContentAPI(Resource):

    def __init__(self):
        self.reqparse = reqparse.RequestParser()

        super(QueryContentAPI, self).__init__()


    def get(self, id):
        logging.warning("QueryID is " + str(id))
        with open('data2.json') as data_file:    
            data = json.load(data_file)
        #logging.warning(request.authentication)
        return data

class UserRegAPI(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('UserID', type=str, required=True,
                                   help='UserID required',
                                   location='json')
        self.reqparse.add_argument('Username', type=str, required=True,
                                   help='Username required',
                                   location='json')
        self.reqparse.add_argument('Password', type=str, required=True,
                                   help='Password required',
                                   location='json')
        self.reqparse.add_argument('Email', type=str, required=True,
                       help='Email required',
                       location='json')
        super(UserRegAPI, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()
        logging.warning(args)
        return {"state": "success"},201
        

        

class UserAuthAPI(Resource):


    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('Username', type=str, required=True,
                                   help='Username required',
                                   location='json')
        self.reqparse.add_argument('Password', type=str, required=True,
                                   help='Password required',
                                   location='json')
        super(UserAuthAPI, self).__init__()

        

    def post(self):
        args = self.reqparse.parse_args()
        
#check with the database
        #use generate_auth_token
        logging.warning('User: ' + args['Username'])
        currentID = Utility.generate_auth_token(args)
        #if (verify_password(currentID, "")):
            #logging.warning("no problem")
        #import chardet
        #logging.warning(chardet.detect(currentID))
#return token
        currentID = currentID.decode('ascii')
        logging.warning("return token")
        
        return {'Token': currentID}, 201


api.add_resource(IdeaAPI, '/api/ideas')
api.add_resource(UserAuthAPI, '/api/login')
api.add_resource(PasswordRecoveryAPI, '/api/login/forget')
api.add_resource(QueryAPI, '/api/ideas/query=<string:queries>')
api.add_resource(QueryContentAPI, '/api/ideas/queryid=<int:id>')
api.add_resource(UserRegAPI, '/api/reg')

