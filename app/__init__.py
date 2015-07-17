from flask import Flask
from flask.ext.cors import CORS

app = Flask(__name__)
app.config["SECRET_KEY"] = "Hello"
CORS(app, resources=r'/api/*', allow_headers=['Authorization', 'Content-Type'])
app.config["MAX_QUERY"] = 10
app.config["CURRENT_QUERY"] = 0


from app import restserver
