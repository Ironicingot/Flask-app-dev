from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisfirstflaskapp'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Brand Rumour\\brand_rumour\\database\\brandrumour.db'    # configure sqlite database
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://brandrumour:brandrumour@localhost:5432/brandrumour'     # configure progresqlite database

app.config['STRIPE_PUBLIC_KEY'] = ''
app.config['STRIPE_SECRET_KEY'] = ''
db = SQLAlchemy(app)       # create the extension

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'br.brandrumours@gmail.com'
app.config['MAIL_PASSWORD'] = 'dsxnohbfrvyzybgn'

from brand_rumour import routes