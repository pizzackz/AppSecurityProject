from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import with_polymorphic

from app.models import Member, Admin, Authentication, AccountStatus, LoginDetails

# IMPORTANT: If you already have data inside your database that overlaps with these sample data,
# please clear them in your database otherwise, issues might arise

# To populate database with all necessary tables and tuples
# Only this function shall be called in run.py to populate our sample data
# Please make sure to create a function for each new tuple you want to create and later call that function in this one
def populate_database(app: Flask, db: SQLAlchemy) -> None:
    # Creates all tables needed
    create_tables(app, db)

    # Here is where you call your functions to seed/ populate the database tables created
    create_member(app, db)
    create_admin(app, db)

    print("Database successfully populated!")


# Creates all tables inside database
def create_tables(app: Flask, db: SQLAlchemy) -> None:
    with app.app_context():
        db.create_all()
    print("Tables successfully created!")


# Create test member data
def create_member(app: Flask, db: SQLAlchemy) -> None:
    with app.app_context():
        try:
            # New member object
            new_member: Member = Member(username="member1", email="member@membertest.com", type="member")
            db.session.add(new_member)
            db.session.flush()
            # print(f"Member created: {new_member}")

            # Create related tuples
            authentication: Authentication = Authentication(id=new_member.id, password_hash=generate_password_hash("membertestpassword"))
            account_status: AccountStatus = AccountStatus(id=new_member.id)
            login_details: LoginDetails = LoginDetails(id=new_member.id)

            # Commit all changes to database
            db.session.add_all([authentication, account_status, login_details])
            db.session.commit()

            # print(f"Authentication for Member created: {authentication}")
            # print(f"Account Status for Member created: {account_status}")
            # print(f"Login Details for Member created: {login_details}")

        except SQLAlchemyError as e:
            db.session.rollback()  # Rollback all changes if any operation fails
            print(f"An error occurred: {e}")


# Create test admin data
def create_admin(app: Flask, db: SQLAlchemy) -> None:
    with app.app_context():
        try:
            # New member object
            new_admin: Admin = Admin(username="admin1", email="admin@admintest.com", type="admin")
            db.session.add(new_admin)
            db.session.flush()
            # print(f"Admin created: {new_admin}")

            # Create related tuples
            authentication: Authentication = Authentication(id=new_admin.id, password_hash=generate_password_hash("admintestpassword"))
            account_status: AccountStatus = AccountStatus(id=new_admin.id)
            login_details: LoginDetails = LoginDetails(id=new_admin.id)

            # Commit all changes to database
            db.session.add_all([authentication, account_status, login_details])
            db.session.commit()

            # print(f"Authentication for Admin created: {authentication}")
            # print(f"Account Status for Admin created: {account_status}")
            # print(f"Login Details for Admin created: {login_details}")
        except SQLAlchemyError as e:
            db.session.rollback()  # Rollback all changes if any operation fails
            print(f"An error occurred: {e}")
