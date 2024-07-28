import random
import base64
import string
import logging
import hashlib
import os

from datetime import datetime, timedelta, timezone
from flask_login import UserMixin
from flask_jwt_extended import create_access_token
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.sql import func
from typing import Optional

from app import db

# Initialise variables
logger = logging.getLogger("tastefully")
DEFAULT_PROFILE_IMAGE_PATH = "static/uploads/profile_pictures/default.png"


# User model acting as superclass to 'Member' and 'Admin' models while also allowing extension for common models like 'Authentication' and 'AccountStatus'
class User(UserMixin, db.Model):
    __tablename__ = "user"

    # Common attributes
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=True)
    google_id = Column(String(255), nullable=True)  # 'NULL' when user does manual sign up
    phone_number = Column(String(20), nullable=True)
    address = Column(String(255), nullable=True)
    postal_code = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=func.current_timestamp(), nullable=False)
    updated_at = Column(DateTime, default=func.current_timestamp(), onupdate=func.current_timestamp(), nullable=False)
    
    type = Column(String(50), default="member", nullable=False)  # "member" or "admin", defaulted to 'member'

    # Defining relationships with other models
    account_status = db.relationship("AccountStatus", back_populates="user", uselist=False, cascade="all, delete-orphan")
    login_details = db.relationship("LoginDetails", back_populates="user", uselist=False, cascade="all, delete-orphan")
    locked_accounts = db.relationship("LockedAccount", back_populates="user", uselist=False, cascade="all, delete-orphan")
    profile_images = db.relationship("ProfileImage", back_populates="user", uselist=False, cascade="all, delete-orphan")

    # Joined Table Inheritance polymorphic properties
    __mapper_args__ = {"polymorphic_identity": "user", "polymorphic_on": type}

    def __repr__(self):
        return f"<User(id='{self.id}', username='{self.username}', type='{self.type}')>"
    

# Member model as subclass to 'User' and to store subscription plan (either standard by default or premium)
class Member(User):
    __tablename__ = "member"

    # ForeignKey reference to 'user.id' and primary key for 'member'
    id = db.Column(Integer, ForeignKey("user.id"), primary_key=True)
    subscription_plan = db.Column(String(50), default="standard", nullable=False)
    subscription_end_date = db.Column(DateTime, nullable=True)

    # Joined Table Inheritance polymorphic properties
    __mapper_args__ = {"polymorphic_identity": "member"}

    def __repr__(self):
        return f"<Member(id='{self.id}', username='{self.username}', subscription_plan='{self.subscription_plan}')>"

    # Methods for CRUD functionalities
    # Create new member
    @staticmethod
    def create(username: str, email: str, password_hash: str, subscription_plan: str = "standard"):
        try:
            # Create new member object
            new_member = Member(username=username, email=email, password_hash=password_hash, subscription_plan=subscription_plan, type="member")
            db.session.add(new_member)
            db.session.flush()

            acc_status = AccountStatus.create(id=new_member.id)
            if not acc_status:
                raise Exception("Failed to create account status record for member")

            profile_image = ProfileImage.create(id=new_member.id)
            if not profile_image:
                raise Exception("Failed to create profile image record for member")

            db.session.commit()

            return new_member
        except Exception as e:
            db.session.rollback()
            logger.error(f"An error occurred while creating member: {e}")
            return None
    
    # Create new member through google signin
    @staticmethod
    def create_by_google(username: str, email: str, google_id: str, google_image_url: str, subscription_plan: str = "standard"):
        try:
            # Create new member object
            new_member = Member(username=username, email=email, google_id=google_id, subscription_plan=subscription_plan, type="member")
            db.session.add(new_member)
            db.session.flush()

            acc_status = AccountStatus.create(id=new_member.id)
            if not acc_status:
                raise Exception("Failed to create account status record for member")

            profile_image = ProfileImage.create_by_google(id=new_member.id, google_url=google_image_url)
            if not profile_image:
                raise Exception("Failed to create profile image record for member")

            db.session.commit()

            return new_member
        except Exception as e:
            db.session.rollback()
            logger.error(f"An error occurred while creating member: {e}")
            return None


# Admin model as subclass to 'User' and to store special 256 hashed string for verification purposes
class Admin(User):
    __tablename__ = "admin"

    # ForeignKey reference to 'user.id' and primary key for 'admin'
    id = db.Column(Integer, ForeignKey("user.id"), primary_key=True)
    admin_key = db.Column(String(255), nullable=True)
    admin_key_expires_at = db.Column(DateTime, nullable=True)

    # Joined Table Inheritance polymorphic properties
    __mapper_args__ = {"polymorphic_identity": "admin"}

    def __repr__(self):
        return f"<Admin(id='{self.id}', username='{self.username}', admin_key='{self.admin_key}')>"

    # Methods for CRUD functionalities
    # Create new admin
    @staticmethod
    def create(username: str, email: str, password_hash: str):
        try:
            # Create new admin object
            new_admin = Admin(username=username, email=email, password_hash=password_hash, type="admin")
            db.session.add(new_admin)
            db.session.flush()

            # Create related records
            acc_status = AccountStatus.create(id=new_admin.id)
            if not acc_status:
                raise Exception("Failed to create account status record for admin")

            profile_image = ProfileImage.create(id=new_admin.id)
            if not profile_image:
                raise Exception("Failed to create profile image record for admin")

            admin_key = new_admin.generate_admin_key()
            if not admin_key:
                raise Exception("Failed to generate an admin key for admin")

            db.session.commit()
            return new_admin
        except Exception as e:
            db.session.rollback()
            print(f"An error occurred: {e}")
            return None

    # Create new admin through google signin
    @staticmethod
    def create_by_google(username: str, email: str, google_id: str, google_image_url: str):
        try:
            # Create new member object
            new_admin = Admin(username=username, email=email, google_id=google_id, type="admin")
            db.session.add(new_admin)
            db.session.flush()

            acc_status = AccountStatus.create(id=new_admin.id)
            if not acc_status:
                raise Exception("Failed to create account status record for admin")

            profile_image = ProfileImage.create_by_google(id=new_admin.id, google_url=google_image_url)
            if not profile_image:
                raise Exception("Failed to create profile image record for admin")
            
            admin_key = new_admin.generate_admin_key()
            if not admin_key:
                raise Exception("Failed to generate an admin key for admin")

            db.session.commit()

            return new_admin
        except Exception as e:
            db.session.rollback()
            logger.error(f"An error occurred while creating admin: {e}")
            return None

    # Generate dynamic one-time use admin key
    def generate_admin_key(self):
        master_key = MasterKey.get_valid_key()
        if not master_key:
            return None
        
        data = f"{master_key}{self.id}{self.username}{self.email}"
        self.admin_key = hashlib.sha256(data.encode()).hexdigest()
        self.admin_key_expires_at = (datetime.now() + timedelta(days=1)).isoformat()
        db.session.commit()

        return data


# AccountStatus model to store important info about current 'User' model's account status such as lock related info or failed login attempts
# related info
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
    
    # Methods for CRUD functionalities
    # Create
    @staticmethod
    def create(id: Column[int]):
        try:
            account_status: AccountStatus = AccountStatus(id=id)
            db.session.add(account_status)
            db.session.commit()
            return account_status
        except Exception as e:
            db.session.rollback()
            print(f"Error occurred when creating new account status: {e}")
            return None


# ProfileImage model to store profile images about user accounts
class ProfileImage(db.Model):
    __tablename__ = "profile_images"

    # ForeignKey reference to 'user.id' and primary key for 'profile_images'
    id = Column(Integer, ForeignKey("user.id"), primary_key=True)
    source = Column(String(20), nullable=False, default="file_system")
    filename = Column(Text, nullable=False, default="default.png")
    google_url = Column(Text, nullable=True)
    updated_at = Column(DateTime, nullable=False, default=func.current_timestamp(), onupdate=func.current_timestamp())

    # Relationship back to 'User'
    user = db.relationship("User", back_populates="profile_images")

    def __repr__(self) -> str:
        return f"<ProfileImage(id='{self.id}', source='{self.source}', filename='{self.filename}', google_url='{self.google_url}', file_hash='{self.file_hash}', updated_at='{self.updated_at}')"

    # Static methods for CRUD functionalities
    # Create
    @staticmethod
    def create(id: Column[int]):
        try:
            profile_image: ProfileImage = ProfileImage(id=id)
            db.session.add(profile_image)
            db.session.commit()
            return profile_image
        except Exception as e:
            db.session.rollback()
            print(f"Error occurred when creating new profile image record: {e}")
            return None

    # Create by google
    @staticmethod
    def create_by_google(id: Column[int], google_url: Column[Text]):
        try:
            profile_image: ProfileImage = ProfileImage(id=id, source="google", google_url=google_url)
            db.session.add(profile_image)
            db.session.commit()
            return profile_image
        except Exception as e:
            db.session.rollback()
            print(f"Error occurred when creating new profile image record: {e}")
            return None


# MasterKey model to store all master keys
class MasterKey(db.Model):
    __tablename__ = "master_key"

    id = db.Column(Integer, primary_key=True)
    value = db.Column(String(255), nullable=False)
    created_at = db.Column(DateTime, default=func.current_timestamp(), nullable=False)
    expires_at = db.Column(DateTime, nullable=False)

    def __repr__(self):
        return f"<MasterKey(id='{self.id}', expires_at='{self.expires_at}')>"

    # Methods for master keys
    # Generate master key value
    @staticmethod
    def generate_master_key():
        new_key = os.urandom(32).hex()
        expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        return MasterKey(value=new_key, expires_at=expires_at)

    # Retrieve any of the valid keys
    @staticmethod
    def get_valid_key():
        current_time = datetime.now().isoformat()
        return MasterKey.query.filter(MasterKey.expires_at > current_time).first()


# LoginDetails model to store info about last login and logout times
class LoginDetails(db.Model):
    __tablename__ = "login_details"

    # ForeignKey reference to 'user.id' and primary key for 'login_details'
    id = Column(Integer, ForeignKey("user.id"), primary_key=True)
    last_login = Column(DateTime, nullable=True)
    last_logout = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=False, nullable=False)

    # Relationship back to 'User'
    user = db.relationship("User", back_populates="login_details")

    def __repr__(self):
        return f"<LoginDetails(id='{self.id}', username='{self.user.username}', last_login='{self.last_login}', last_logout='{self.last_logout}')>"
    
    # Static methods for CRUD functionalities
    # Create
    @staticmethod
    def create(id: Column[int]):
        try:
            login_details: LoginDetails = LoginDetails(id=id)
            db.session.add(login_details)
            db.session.commit()
            return login_details
        except Exception as e:
            db.session.rollback()
            print(f"Error occurred when creating new locked account record: {e}")
            return None


# LockedAccount model to store locking related information about all locked accounts, including admin accounts
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

    # Static methods
    # Create
    @staticmethod
    def create(id: Column[int], locked_reason: str, locker_id: Optional[Column[int]] = None):
        try:
            locked_account: LockedAccount = LockedAccount(id=id, locker_id=locker_id, locked_reason=locked_reason)
            db.session.add(locked_account)
            db.session.commit()
            return locked_account
        except Exception as e:
            db.session.rollback()
            print(f"Error occurred when locking account: {e}")
            return None


# PassowrdResetToken model to store allowed password reset tokens whenever password reset is requested
class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_token"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), nullable=False)
    token_hash = Column(String(255), nullable=False, unique=True)
    created_at = Column(DateTime, default=func.current_timestamp(), nullable=False)
    expires_at = Column(DateTime, nullable=False)

    def __repr__(self):
        return f'<PasswordResetToken(email={self.email}, expires_at={self.expires_at})>'
    
    @staticmethod
    def create(email: str):
        # Generate secure token
        token = create_access_token(identity={'email': email}, expires_delta=timedelta(hours=1))
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Calculate expiration time
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        # Create token record
        try:
            reset_token = PasswordResetToken(email=email, token_hash=token_hash, expires_at=expires_at)
            db.session.add(reset_token)
            db.session.commit()
            return token
        except Exception as e:
            db.session.rollback()
            print(f"Error occurred when creating new token record: {e}")
            return None


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
        db.DateTime, nullable=False, default=func.current_timestamp()
    )
    user_created = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # Standard or Premium
    calories = db.Column(db.Integer, nullable=False)
    prep_time = db.Column(db.Integer, nullable=False)  # in minutes

    def __repr__(self):
        return f"Recipe('{self.name}')"


class RecipeDeleted(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ingredients = db.Column(
        db.Text, nullable=False
    )  # Storing ingredients as JSON string
    instructions = db.Column(db.Text, nullable=False)
    picture = db.Column(db.String(100))  # Assuming picture URL
    date_created = db.Column(db.DateTime, nullable=False)
    date_deleted = db.Column(db.DateTime, nullable=False, default=func.current_timestamp())
    user_created = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # Standard or Premium
    calories = db.Column(db.Integer, nullable=False)
    prep_time = db.Column(db.Integer, nullable=False)  # in minutes

    def __repr__(self):
        return f"Recipe('{self.name}')"


# To store the configuration status of recipes (Lock recipes)
class RecipeConfig(db.Model):
    name = db.Column(db.String(100), primary_key=True, nullable=False)
    status = db.Column(db.String(5), nullable=False)

    def __repr__(self):
        return f"{self.name}: {self.status}"


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    rating = db.Column(db.Integer, nullable=False, default=5)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=func.current_timestamp(), nullable=False)

    def __repr__(self):
        return f'<Feedback {self.name}>'


# Payment model to store payment related information
class Payment(db.Model):
    __tablename__ = "payments"
    id = db.Column(db.Integer, primary_key=True)
    stripe_payment_id = db.Column(db.String(255), unique=True, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    created_at = db.Column(
        db.DateTime, default=func.current_timestamp(), nullable=False
    )

    def __repr__(self):
        return f"Payment(stripe_payment_id='{self.stripe_payment_id}', amount={self.amount}, currency='{self.currency}', status='{self.status}', timestamp='{self.created_at}')"


class MenuItem(db.Model):
    __tablename__ = "menu_items"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image = db.Column(db.String(255), nullable=True)
    ingredient_list = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<MenuItem {self.name}>"


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(255), nullable=False)
    customer_email = db.Column(db.String(255), nullable=True)
    address = db.Column(db.String(255), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    delivery_date = db.Column(db.String(20), nullable=False)
    delivery_time = db.Column(db.String(20), nullable=False)
    selected_items = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=func.current_timestamp())

    items = db.relationship("OrderItem", backref="order", lazy=True)

    def __repr__(self):
        return f"<Order {self.id}>"


class OrderItem(db.Model):
    __tablename__ = "order_items"
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey("menu_items.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    menu_item = db.relationship("MenuItem", backref="order_items")

    def __repr__(self):
        return f"<OrderItem {self.id}>"


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    refresh_token = db.Column(db.String(255), nullable=False)