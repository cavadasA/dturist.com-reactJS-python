from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # name = db.Column(db.String(80), unique=False, nullable=True)
    password = db.Column(db.String(80), unique=False, nullable=False)
    is_active = db.Column(db.Boolean(), unique=False, nullable=False)

    @classmethod
    def create_user(cls, email, password):
        user = cls()
        user.email = email
        user.password = password
        # user.name = name
        user.is_active = True

        db.session.add(user)
        db.session.commit()

    @classmethod
    def get_with_login_credentials(cls, email, password):
        return cls.query.filter_by(email=email).filter_by(password=password).one_or_none()
    
    @classmethod
    def get(cls, id):
        return cls.query.get(id)

    def __repr__(self):
        return '<User %r>' % self.username

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            # "name": self.name
            # do not serialize the password, its a security breach
        }

    
