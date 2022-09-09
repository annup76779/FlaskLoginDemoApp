from flask import Flask, current_app, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///main.db"
jwt = JWTManager(app)
app.config["JWT_SECRET_KEY"] = "Kt0OMErs_SsNGUO9NEXBJBdE-rB-bz-XDs5zgWv0NiC_hbjQbJrPOlglK4lZvgk3PME8DsyqWos"
migrate = Migrate(app, db)
crypt = Bcrypt(app)

from model import User

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user

@jwt.user_lookup_loader # decorator
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.get(identity)

@app.route("/login", methods=["POST"])
def login():
    user_email = request.form.get("user_email").strip()
    password = request.form.get("password")

    if user_email and password:
        user = User.query.filter_by(email = user_email).one_or_none()
        if user.verify(password):
            access_token = create_access_token(
                identity=user.user_id
            )
            return jsonify(status = True, access_token=access_token)

@app.route("/register", methods=["POST"])
def register():
    user_email = request.form.get("user_email").strip()
    name = request.form.get("name").strip()
    password = request.form.get("password")

    user = User(email= user_email, name=name, password=password)

    db.session.add(user)
    db.session.commit()
    return jsonify(status=True, msg="Resgistered successfully.")


@app.route("/get_user_name")
@jwt_required()
def get_user_name():
    user = get_current_user()
    return jsonify(status=True, name = user.name, msg="Perfect")