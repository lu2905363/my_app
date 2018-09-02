from random import randint
from sqlalchemy.exc import IntegrityError
from faker import Faker
from werkzeug.security import generate_password_hash
from app import db
from app.models import User, Post


def users(count=100):
    fake = Faker()
    i= 0
    while i < count:
        u = User(email=fake.email(), username=fake.user_name(), password_hash=generate_password_hash('password'),
                 confirmed=True, name=fake.name(), location=fake.city(), about_me=fake.text(),
                 member_since=fake.past_date())
        db.session.add(u)
        try:
            db.session.commit()
            i += 1
        except IntegrityError:  # in case of duplicate user information
            db.session.rollback()


def posts(count=100):
    fake = Faker()
    user_count = User.query.count()
    for i in range(count):
        u = User.query.offset(randint(0, user_count-1)).first()
        p = Post(body=fake.text(), timestamp=fake.past_date(), author=u)
        db.session.add(p)
    db.session.commit()