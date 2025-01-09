
from flask import Flask
from flask_jwt_extended import JWTManager

import controllers.api
from config import Config
from extensions import db
from utils.common_utils import check_connection

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'your_secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 86400



app.config['SQLALCHEMY_DATABASE_URI'] = Config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


jwt = JWTManager(app)
db.init_app(app)

check_connection()

app.register_blueprint(controllers.api.account_bp, url_prefix='/account')

if __name__ == '__main__':
    app.run(debug=True, host=Config.HOST, port=Config.PORT)

