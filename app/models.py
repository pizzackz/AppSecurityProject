import os
import secrets
import string
import logging
import hashlib

from datetime import datetime, timedelta, timezone
from flask_login import UserMixin
from flask_jwt_extended import create_access_token
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.sql import func
from typing import Optional

from app import db


logger = logging.getLogger("tastefully")


# User model acting as superclass to 'Member' and 'Admin' models while also allowing extension for common models like 'Authentication' and 'AccountStatus'
class User(UserMixin, db.Model):
    __tablename__ = "user"

    # Common attributes
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), default="", nullable=False)
    google_id = Column(String(255), nullable=True)  # 'NULL' when user does manual sign up
    profile_picture = Column(String(255), default=os.path.join("static", "uploads", "profile_pictures", "ZGVmYXVsdA.png"), nullable=True)
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

    # Joined Table Inheritance polymorphic properties
    __mapper_args__ = {"polymorphic_identity": "user", "polymorphic_on": type}

    def __repr__(self):
        return f"<User(id='{self.id}', username='{self.username}', type='{self.type}')>"
    

# Member model as subclass to 'User' and to store subscription plan (either standard by default or premium)
class Member(User):
    __tablename__ = "member"

    # ForeignKey reference to 'user.id' and primary key for 'member'
    id = Column(Integer, ForeignKey("user.id"), primary_key=True)
    subscription_plan = Column(String(50), default="standard", nullable=False)

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

            login_details = LoginDetails.create(id=new_member.id)
            if not login_details:
                raise Exception("Failed to create login details record for member")

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
    id = Column(Integer, ForeignKey("user.id"), primary_key=True)
    master_key = Column(String(64), default=lambda: Admin.generate_master_key(), nullable=False)

    # Joined Table Inheritance polymorphic properties
    __mapper_args__ = {"polymorphic_identity": "admin"}

    def __repr__(self):
        return f"<Admin(id='{self.id}', username='{self.username}', master_key='{self.master_key}')>"

    # Methods for CRUD functionalities
    # Generate master keys
    @staticmethod
    def generate_master_key(length: int = 64) -> str:
        """Generate a secure random master key"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(alphabet) for _ in range(length))

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

            login_details = LoginDetails.create(id=new_admin.id)
            if not login_details:
                raise Exception("Failed to create login details record for admin")

            db.session.commit()
            return new_admin
        except Exception as e:
            db.session.rollback()
            print(f"An error occurred: {e}")
            return None


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

    # Update login
    @staticmethod
    def login(id: Column[int]):
        try:
            login_details: LoginDetails = LoginDetails.query(id)
            if login_details:
                login_details.last_login = datetime.now(timezone.utc)
                login_details.is_active = True
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
