from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

from app.models import User, Member


# IMPORTANT: If you already have data inside your database that overlaps with these sample data,
# please clear them in your database otherwise, issues might arise

# To populate database with all necessary tables and tuples
# Only this function shall be called in run.py to populate our sample data
# Please make sure to create a function for each new tuple you want to create and later call that function in this one
def populate_database(app: Flask, db: SQLAlchemy) -> None:
    # Creates all tables needed
    create_tables(app, db)

    # Here is where you call your functions
    create_member(app, db)
    # create_admin(app, db)

    print("Database successfully populated!")


# Creates all tables inside database
def create_tables(app: Flask, db: SQLAlchemy) -> None:
    with app.app_context():
        db.create_all()
    print("Tables successfully created!")


# Creates a new member tuple and its tuple in other related models
def create_member(app: Flask, db: SQLAlchemy) -> None:
    with app.app_context():
        # Create new 'Member' along with 'User'
        new_user: User = User(username="member1", email="member@membertest.com", user_type="member")
        new_member: Member = Member()
        print(f"User created: {new_user}")

        db.session.add(new_user)
        db.session.commit()

        # Create member from new_user's user_id, subscription_plan defaulted to "standard"
        db.session.add(new_member)
        new_member.user = new_user
        db.session.commit()
        print(f"Member created: {new_member}")

        # Create tuples in Authentication, AccountStatus, LoginDetails that relate to user_id
        # authentication: Authentication = Authentication(user_id=new_user.user_id, password_hash=generate_password_hash("testmemberpassword"))
        # account_status: AccountStatus = AccountStatus(user_id=new_user.user_id)
        # login_details: LoginDetails = LoginDetails(user_id=new_user.user_id)

        # db.session.add_all((new_member, authentication, account_status, login_details))
        db.session.commit()

        # print(f"All other member related details: {', '.join((str(authentication), str(account_status), str(login_details)))}")


# Creates a new admin tuple and its tuple in other related models
# def create_admin(app: Flask, db: SQLAlchemy) -> None:
#     with app.app_context():
#         # Create new user of type "member" -- "member" is default
#         new_user: User = User(username="admin1", email="admin@admintest.com", user_type="admin")
#         print(f"User created: {new_user}")

#         db.session.add(new_user)
#         db.session.commit()

#         # Create member from new_user's user_id, subscription_plan defaulted to "standard"
#         new_admin: Admin = Admin(user_id=new_user.user_id, master_key="testadminmasterkeyvalue")
#         new_admin.user.append(new_user)
#         print(f"Admin created: {new_admin}")

#         # Create tuples in Authentication, AccountStatus, LoginDetails that relate to user_id
#         authentication: Authentication = Authentication(user_id=new_user.user_id, password_hash=generate_password_hash("testadminpassword"))
#         account_status: AccountStatus = AccountStatus(user_id=new_user.user_id)
#         login_details: LoginDetails = LoginDetails(user_id=new_user.user_id)

#         db.session.add_all((new_admin, authentication, account_status, login_details))
#         db.session.commit()

#         print(f"All other admin related details: {', '.join((str(authentication), str(account_status), str(login_details)))}")

