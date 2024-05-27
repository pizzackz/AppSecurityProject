from flask_sqlalchemy import SQLAlchemy
from . import db
import datetime


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
        self.type = recipe_type

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
