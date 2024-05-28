import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.sql import func

from app import db


# User model acting as superclass to 'Member' and 'Admin' models while also allowing extension for common models like 'Authentication' and 'AccountStatus'
class User(db.Model, UserMixin):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    profile_picture = db.Column(
        db.String(255), nullable=True
    )  # Store path/URL to image
    phone_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    postal_code = db.Column(db.String(20), nullable=True)
    created_at = db.Column(
        db.DateTime, default=func.current_timestamp(), nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
        nullable=False,
    )
    type = db.Column(db.String(50), nullable=False)  # Discriminator column

    # Defining relationships with other models
    authentication = db.relationship(
        "Authentication",
        uselist=False,
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="[Authentication.user_id]",
    )
    account_status = db.relationship(
        "AccountStatus",
        uselist=False,
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="[AccountStatus.user_id]",
    )
    login_details = db.relationship(
        "LoginDetails",
        uselist=False,
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="[LoginDetails.user_id]",
    )
    member = db.relationship(
        "Member",
        uselist=False,
        back_populates="user",
        cascade="all, delete-orphan",
        primaryjoin="User.user_id == Member.user_id",
    )
    admin = db.relationship(
        "Admin",
        uselist=False,
        back_populates="user",
        cascade="all, delete-orphan",
        primaryjoin="User.user_id == Admin.user_id",
    )
    locked_accounts = db.relationship(
        "LockedAccount",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="[LockedAccount.user_id]",
    )

    __mapper_args__ = {"polymorphic_identity": "user", "polymorphic_on": type}

    def __repr__(self):
        return f"User('{self.username}')"


# Admin model as subclass to 'User' and to store special 256 hashed string for verification purposes
class Admin(db.Model, UserMixin):
    __tablename__ = "admins"
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.user_id"), primary_key=True, nullable=False
    )
    master_key = db.Column(db.String(64), nullable=False)

    # Relationship with 'User' model
    user = db.relationship(
        "User", back_populates="admin", primaryjoin="Admin.user_id == User.user_id"
    )
    locked_accounts = db.relationship(
        "LockedAccount",
        back_populates="locker",
        foreign_keys="[LockedAccount.locker_id]",
    )

    __mapper_args__ = {
        "polymorphic_identity": "admin",
    }

    def __repr__(self):
        return f"Admin('{self.user.username}')"


# Member model as subclass to 'User' and to store subscription plan (either standard by default or premium)
class Member(db.Model, UserMixin):
    __tablename__ = "members"
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.user_id"), primary_key=True, nullable=False
    )
    subscription_plan = db.Column(
        db.String(50), default="standard", nullable=False
    )  # Allow "standard" or "premium"
    user = db.relationship(
        "User", back_populates="member", primaryjoin="Member.user_id == User.user_id"
    )

    __mapper_args__ = {
        "polymorphic_identity": "member",
    }

    def __repr__(self):
        return f"Member('{self.user.username}')"


# Authentication model to store 'password_hash' (mandatory) for manual sign in & 'google_id' for google sign in
class Authentication(db.Model):
    __tablename__ = "authentication"
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.user_id"), primary_key=True, nullable=False
    )
    password_hash = db.Column(db.String(255), default="", nullable=False)
    google_id = db.Column(
        db.String(255), nullable=True
    )  # 'NULL' when user does manual sign up
    user = db.relationship(
        "User",
        back_populates="authentication",
        primaryjoin="Authentication.user_id == User.user_id",
    )

    def __repr__(self):
        return f"Authentication('{self.user.username}')"


# AccountStatus model to store important info about current 'User' model's account status such as lock related info or failed login attempts
# related info
class AccountStatus(db.Model):
    __tablename__ = "account_status"
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.user_id"), primary_key=True, nullable=False
    )
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    lockout_time = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_failed_login_attempt = db.Column(db.DateTime, nullable=True)

    user = db.relationship(
        "User",
        back_populates="account_status",
        primaryjoin="AccountStatus.user_id == User.user_id",
    )

    def __repr__(self):
        return f"AccountStatus('{self.user.username}')"


# LockedAccount model to store locking related information about all locked accounts, including admin accounts
class LockedAccount(db.Model):
    __tablename__ = "locked_accounts"
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.user_id"), primary_key=True, nullable=False
    )
    locker_id = db.Column(
        db.Integer, db.ForeignKey("admins.user_id"), primary_key=True, nullable=False
    )
    locked_reason = db.Column(db.Text, nullable=False)
    locked_time = db.Column(
        db.DateTime, default=func.current_timestamp(), nullable=False
    )

    user = db.relationship(
        "User",
        back_populates="locked_accounts",
        primaryjoin="LockedAccount.user_id == User.user_id",
    )
    locker = db.relationship(
        "Admin",
        back_populates="locked_accounts",
        primaryjoin="LockedAccount.locker_id == Admin.user_id",
    )

    def __repr__(self):
        return f"LockedAccount('{self.user.username}', '{self.locker.user.username}')"


# LoginDetails model to store info about last login and logout times
class LoginDetails(db.Model):
    __tablename__ = "login_details"
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), primary_key=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_logout = db.Column(db.DateTime, nullable=True)
    user = db.relationship(
        "User",
        back_populates="login_details",
        primaryjoin="LoginDetails.user_id == User.user_id",
    )

    def __repr__(self):
        return f"LoginDetails('{self.user.username}')"


# Recipe model to store recipe related information
class Recipe(db.Model):
    def __init__(
        self,
        name: str,
        ingredients: str,
        instructions: str,
        picture: str,
        calories: int,
        prep_time: int,
        recipe_type: str,
    ) -> None:
        self.name = name
        self.ingredients = ingredients
        self.instructions = instructions
        self.picture = picture
        self.calories = calories
        self.prep_time = prep_time
        self.recipe_type = recipe_type
        self.user_created = 'JohnDoe1'

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
