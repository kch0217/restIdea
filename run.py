#!flask/bin/python
from app import app
from flask_restful import Api, Resource, reqparse, fields, marshal
app.run(debug=True)
