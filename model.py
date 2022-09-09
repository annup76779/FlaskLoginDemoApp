from wsgi import app, db, crypt
import sqlalchemy as sa


class User(db.Model):
    __tablename__ = 'users'

    user_id = sa.Column(sa.Integer, primary_key = True, autoincrement = True)
    email = sa.Column(sa.String(100), unique = True)
    name = sa.Column(sa.String(100), nullable = False)
    password = sa.Column(sa.String(60, _warn_on_bytestring=True), nullable = False)

    def __init__(self, email, name, password): # 76779
        self.email = email
        self.name = name
        if isinstance(password, str):
            self.password = crypt.generate_password_hash(password)
        else:
            raise ValueError("Password must be a string")

    def verify(self, password):
        return crypt.check_password_hash(self.password, password)