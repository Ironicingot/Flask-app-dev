from brand_rumour import db
from datetime import datetime
from flask_login import UserMixin

class User(db.Model, UserMixin):       # User will inherit from db model
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique = True, nullable = False)
    email = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable = False)
    date_created = db.Column(db.DateTime, default = datetime.utcnow)

    def __repr__(self):
        return f'{self.username} : {self.email} : {self.date_created.strftime("%d/%m/%Y, %H:%M:%S")}'       # strftime is to format the time