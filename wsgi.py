from flask import Flask, current_app, jsonify, request, render_template, redirect, url_for, flash, Markup
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

migrate = Migrate()
crypt = Bcrypt()

# SQLAlchemy setup
db = SQLAlchemy()
print(__name__)


def create_flask_app_with_flask_login_support():
    # import Flask_Login
    from flask_login import LoginManager, login_required, login_user, logout_user, current_user

    # create Flask App
    app = Flask(__name__)

    # SQLAlchemy SETUP
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///main.db"
    db.init_app(app)

    migrate.init_app(app, db)
    # bellow command in terminal before you run app -
    ## flask db upgrade ##

    crypt.init_app(app)

    # setting up flask login
    login_manager = LoginManager()
    # set the secret key to use Flask Session
    app.config["SECRET_KEY"] = "Kt0OMErs_SsNGUO9NEXBJBdE-rB-bz-XDs5zgWv0NiC_hbjQbJrPOlglK4lZvgk3PME8DsyqWos"

    login_manager.init_app(app)  # initializing the login manager
    login_manager.session_protection = "strong"
    login_manager.login_view = "login"
    login_manager.login_message_category = "info"
    login_manager.login_message = "Please login to go further!"

    from model import User
    @login_manager.user_loader
    def load_user(user_id):
        user = User.query.get(user_id)
        return user

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            user_email = request.form.get("email").strip()
            password = request.form.get("password")

            if user_email and password:
                user = User.query.filter_by(email=user_email).one_or_none()
                if user is None:
                    flash(Markup(f"Incorrect User Email! <a href='{url_for('register')}'>Register</a>"))
                else:
                    # verify the hashed password
                    if user.verify(password):
                        login_user(user)
                        return redirect(url_for('home'))
                    else:
                        flash("Incorrect User Password!")
                        return redirect(request.url)
            else:
                flash("Please enter all required fields!")
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            user_email = request.form.get("email").strip()
            name = request.form.get("name").strip()
            password = request.form.get("password")

            user = User(email=user_email, name=name, password=password)

            db.session.add(user)
            db.session.commit()
            flash(f"{user_email} registered successfully")
            return redirect(url_for('login'))
        return render_template("register.html")

    @app.route("/home")
    @login_required
    def home():
        # get the User class object of the currently logged_in user
        # you can get the current user using the `current_user` property of Flask_Login
        user = current_user
        return render_template("home.html", user=user)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("User Logged Out")
        return redirect(url_for("index"))

    return app


# ----------------------------------------------------------------
# use this function only if you want to use JWT authorization
# ----------------------------------------------------------------
def create_flask_app_with_jwt_authorization():
    # import JWT EXTENDED
    from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_current_user

    # create the FLASK APP
    app = Flask(__name__)

    # SQLAlchemy setup
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///main.db"
    db.init_app(app)

    # migration setup
    migrate.init_app(app, db)

    # Cryptography SetUp
    # You should use this setup to hash the password at all
    crypt.init_app(app)

    # JWT SETUP
    jwt = JWTManager(app)
    app.config["JWT_SECRET_KEY"] = "Kt0OMErs_SsNGUO9NEXBJBdE-rB-bz-XDs5zgWv0NiC_hbjQbJrPOlglK4lZvgk3PME8DsyqWos"

    from model import User

    # loads the User from identity lookup
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        return user

    # verify the user identity and return the identified user object
    @jwt.user_lookup_loader  # decorator
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(identity)

    @app.route("/login", methods=["POST"])
    def login():
        user_email = request.form.get("user_email").strip()
        password = request.form.get("password")

        if user_email and password:
            user = User.query.filter_by(email=user_email).one_or_none()

            # verify the hashed password
            if user.verify(password):
                access_token = create_access_token(
                    identity=user.user_id
                )
                return jsonify(status=True, access_token=access_token)

    @app.route("/register", methods=["POST"])
    def register():
        user_email = request.form.get("user_email").strip()
        name = request.form.get("name").strip()
        password = request.form.get("password")

        user = User(email=user_email, name=name, password=password)

        db.session.add(user)
        db.session.commit()
        return jsonify(status=True, msg="Resgistered successfully.")

    @app.route("/get_user_name")
    @jwt_required()
    def get_user_name():
        user = get_current_user()
        return jsonify(status=True, name=user.name, msg="Perfect")

    return app


app = create_flask_app_with_flask_login_support()
