import os
import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.sql import func

from app import db

print(os.path.join("static", "uploads", "customer", "profile_pictures", "default"))

# User model acting as superclass to 'Member' and 'Admin' models while also allowing extension for common models like 'Authentication' and 'AccountStatus'
<<<<<<< Updated upstream
class User(db.Model, UserMixin):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    user_type = db.Column(db.String(50), default="member", nullable=False)  # "member" or "admin", defaulted to 'member'
    email = db.Column(db.String(255), unique=True, nullable=False)
    profile_picture = db.Column(db.String(255), default=os.path.join("static", "uploads", "profile_pictures", "ZGVmYXVsdA.png"), nullable=False)  # Store path/URL to image
    phone_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    postal_code = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=func.current_timestamp(), nullable=False)
    updated_at = db.Column(db.DateTime, default=func.current_timestamp(), onupdate=func.current_timestamp(), nullable=False)

    # Defining relationships with other models
    member = db.relationship("Member", back_populates="user", uselist=False)
    # admin = db.relationship("Admin", back_populates="users", uselist=False)
    # authentication = db.relationship("Authentication", back_populates="users", uselist=False)
    # account_status = db.relationship("AccountStatus", back_populates="users", uselist=False)
    # login_details = db.relationship("LoginDetails", back_populates="users", uselist=False)
    # locked_accounts = db.relationship("LockedAccount", back_populates="users", cascade="all, delete-orphan")

    def __repr__(self):
        return f"User(user_id=\"{self.user_id}\", username=\"{self.username}\", user_type=\"{self.user_type}\")"


# Member model as subclass to 'User' and to store subscription plan (either standard by default or premium)
class Member(db.Model, UserMixin):
    __tablename__ = "members"
    member_id = db.Column(db.Integer, primary_key=True, nullable=False)
    subscription_plan = db.Column(db.String(50), default="standard", nullable=False)  # Allow "standard" or "premium"
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)

    # Define relationship back to User
    user = db.relationship("User", back_populates="member")

    def __repr__(self):
        return f"Member('member_id=\"{self.member_id}\", username=\"{self.user.username}\", plan=\"{self.subscription_plan}\")"


# # Admin model as subclass to 'User' and to store special 256 hashed string for verification purposes
# class Admin(db.Model, UserMixin):
#     __tablename__ = "admins"
#     user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), primary_key=True, nullable=False)
#     master_key = db.Column(db.String(64), nullable=False)

#     # Define relationship back to User
#     user = db.relationship("User", back_populates="admins")

#     def __repr__(self):
#         return f"Admin(username='{self.user.username}', master_key='{self.master_key}')"


# # Authentication model to store 'password_hash' (mandatory) for manual sign in & 'google_id' for google sign in
# class Authentication(db.Model):
#     __tablename__ = "authentication"
#     user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), primary_key=True, nullable=False)
#     password_hash = db.Column(db.String(255), default="", nullable=False)
#     google_id = db.Column(db.String(255), nullable=True)  # 'NULL' when user does manual sign up

#     # def __repr__(self):
#     #     return f"Authentication('{self.user.username}')"


# # AccountStatus model to store important info about current 'User' model's account status such as lock related info or failed login attempts
# # related info
# class AccountStatus(db.Model):
#     __tablename__ = "account_status"
#     user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), primary_key=True, nullable=False)
#     is_locked = db.Column(db.Boolean, default=False, nullable=False)
#     lockout_time = db.Column(db.DateTime, nullable=True)
#     failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
#     last_failed_login_attempt = db.Column(db.DateTime, nullable=True)

#     # def __repr__(self):
#     #     return f"AccountStatus('{self.user.username}')"


# # LockedAccount model to store locking related information about all locked accounts, including admin accounts
# class LockedAccount(db.Model):
#     __tablename__ = "locked_accounts"
#     user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), primary_key=True, nullable=False)
#     locker_id = db.Column(db.Integer, db.ForeignKey("admins.user_id"), primary_key=True, nullable=False)
#     locked_reason = db.Column(db.Text, nullable=False)
#     locked_time = db.Column(db.DateTime, default=func.current_timestamp(), nullable=False)

#     # 'locker's relationship with Admin model
#     locker = db.relationship("Admin", back_populates="locked_accounts")

#     # def __repr__(self):
#     #     return f"LockedAccount('{self.user.username}', '{self.locker.user.username}')"


# # LoginDetails model to store info about last login and logout times
# class LoginDetails(db.Model):
#     __tablename__ = "login_details"
#     user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), primary_key=True)
#     last_login = db.Column(db.DateTime, nullable=True)
#     last_logout = db.Column(db.DateTime, nullable=True)

#     # def __repr__(self):
#     #     return f"LoginDetails('{self.user.username}')"
=======
class User(UserMixin, db.Model):
    __tablename__ = "user"

    # Common attributes
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    profile_picture = Column(String(255), default=os.path.join("static", "uploads", "profile_pictures", "default.png"), nullable=True)
    phone_number = Column(String(20), nullable=True)
    address = Column(String(255), nullable=True)
    postal_code = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=func.current_timestamp(), nullable=False)
    updated_at = Column(DateTime, default=func.current_timestamp(), onupdate=func.current_timestamp(), nullable=False)
    type = Column(String(50), default="member", nullable=False)  # "member" or "admin", defaulted to 'member'

    # Defining relationships with other models
    authentication = db.relationship("Authentication", back_populates="user", uselist=False, cascade="all, delete-orphan")
    account_status = db.relationship("AccountStatus", back_populates="user", uselist=False, cascade="all, delete-orphan")
    login_details = db.relationship("LoginDetails", back_populates="user", uselist=False, cascade="all, delete-orphan")
    locked_accounts = db.relationship("LockedAccount", back_populates="user", uselist=False, cascade="all, delete-orphan")

    # Joined Table Inheritance polymorphic properties
    __mapper_args__ = {
        "polymorphic_identity": "user",
        "polymorphic_on": type
    }

    def __repr__(self):
        return f"<User(id='{self.id}', username='{self.username}', type='{self.type}')>"


# Member model as subclass to 'User' and to store subscription plan (either standard by default or premium)
class Member(User):
    __tablename__ = "member"

    # ForeignKey reference to 'user.id' and primary key for 'member'
    id = Column(Integer, ForeignKey("user.id"), primary_key=True)
    subscription_plan = Column(String(50), default="standard", nullable=False)

    # Joined Table Inheritance polymorphic properties
    __mapper_args__ = {
        "polymorphic_identity": "member"
    }

    def __repr__(self):
        return f"<Member(id='{self.id}', username='{self.username}', subscription_plan='{self.subscription_plan}')>"


# Admin model as subclass to 'User' and to store special 256 hashed string for verification purposes
class Admin(User):
    __tablename__ = "admin"

    # ForeignKey reference to 'user.id' and primary key for 'admin'
    id = Column(Integer, ForeignKey("user.id"), primary_key=True)
    master_key = Column(String(255), default="standard", nullable=False)

    # Joined Table Inheritance polymorphic properties
    __mapper_args__ = {
        "polymorphic_identity": "admin"
    }

    def __repr__(self):
        return f"<Admin(id='{self.id}', username='{self.username}', master_key='{self.master_key}')>"


# Authentication model to store 'password_hash' (mandatory) for manual sign in & 'google_id' for google sign in
class Authentication(db.Model):
    __tablename__ = "authentication"

    # ForeignKey reference to 'user.id' and primary key for 'authentication'
    id = Column(Integer, ForeignKey("user.id"), primary_key=True, nullable=False)
    password_hash = Column(String(255), default="", nullable=False)
    google_id = Column(String(255), nullable=True)  # 'NULL' when user does manual sign up

    # Relationship back to 'User'
    user = db.relationship("User", back_populates="authentication")

    def __repr__(self):
        return f"<Authentication(id='{self.id}', username='{self.user.username}', password_hash='{self.password_hash}')>"


# # AccountStatus model to store important info about current 'User' model's account status such as lock related info or failed login attempts
# # related info
class AccountStatus(db.Model):
    __tablename__ = "account_status"

    # ForeignKey reference to 'user.id' and primary key for 'account_status'
    id = Column(Integer, ForeignKey("user.id"), primary_key=True, nullable=False)
    is_locked = Column(Boolean, default=False, nullable=False)
    lockout_time = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    last_failed_login_attempt = Column(DateTime, nullable=True)

    # Relationship back to 'User'
    user = db.relationship("User", back_populates="account_status")

    def __repr__(self):
        return f"<AccountStatus(id='{self.id}', username='{self.user.username}', locked='{self.is_locked}')>"


# # LockedAccount model to store locking related information about all locked accounts, including admin accounts
class LockedAccount(db.Model):
    __tablename__ = "locked_accounts"

    # ForeignKey references to 'user.id' and 'admin.id', and primary keys for 'locked_accounts'
    id = Column(Integer, ForeignKey("user.id"), primary_key=True, nullable=False)
    locker_id = Column(Integer, ForeignKey("admin.id"), primary_key=True, nullable=True)
    locked_reason = Column(Text, nullable=False)
    locked_time = Column(DateTime, default=func.current_timestamp(), nullable=False)

    # Relationship 'id' back to 'User', 'locker' back to 'Admin'
    user = db.relationship("User", back_populates="locked_accounts")
    locker = db.relationship("Admin", back_populates="locked_accounts", foreign_keys=[locker_id])

    def __repr__(self):
        return f"<LockedAccount(id='{self.id}', locker_id='{self.locker_id}', locked_reason='{self.locked_reason}')>"


# # LoginDetails model to store info about last login and logout times
class LoginDetails(db.Model):
    __tablename__ = "login_details"

    # ForeignKey reference to 'user.id' and primary key for 'login_details'
    id = Column(Integer, ForeignKey("user.id"), primary_key=True)
    last_login = Column(DateTime, nullable=True)
    last_logout = Column(DateTime, nullable=True)

    # Relationship back to 'User'
    user = db.relationship("User", back_populates="login_details")

    def __repr__(self):
        return f"<LoginDetails(id='{self.id}', username='{self.user.username}', last_login='{self.last_login}', last_logout='{self.last_logout}')>"
>>>>>>> Stashed changes


# Recipe model to store recipe related information
class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ingredients = db.Column(
        db.Text, nullable=False
    )  # Storing ingredients as JSON string
    instructions = db.Column(db.Text, nullable=False)
    picture = db.Column(db.String(100))  # Assuming picture URL
    date_created = db.Column(
        db.DateTime, nullable=False, default=datetime.datetime.utcnow
    )
    user_created = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # Standard or Premium
    calories = db.Column(db.Integer, nullable=False)
    prep_time = db.Column(db.Integer, nullable=False)  # in minutes

    def __repr__(self):
        return f"Recipe('{self.name}')"


# Creating the database tables
