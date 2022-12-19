from wsgi import db, crypt
import sqlalchemy as sa
from flask_login import UserMixin


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    user_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    email = sa.Column(sa.String(100), unique=True)
    name = sa.Column(sa.String(100), nullable=False)
    password = sa.Column(sa.String(60, _warn_on_bytestring=True), nullable=False)

    def __init__(self, email, name, password):  # 76779
        self.email = email
        self.name = name

        # hash the provided password
        self.password = crypt.generate_password_hash(str(password))

    def verify(self, password):
        # verify the hashed password
        return crypt.check_password_hash(self.password, password)

    def get_id(self):
        return self.user_id

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name