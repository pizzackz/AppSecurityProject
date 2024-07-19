from wtforms import Form, StringField, FileField, TextAreaField, IntegerField, SelectField, DecimalField, SubmitField, validators, HiddenField, DateField, TimeField, SelectMultipleField, IntegerRangeField, BooleanField
from wtforms.validators import DataRequired, Length, NumberRange
from flask_wtf import FlaskForm

from app.forms.validators import six_digit_postal_code_validator, phone_number_validator


# Create recipe form for members and admin, can double as Update recipe form
class CreateRecipeForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=20)], render_kw={"class": "form-control"})
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    instructions = TextAreaField("Instructions", validators=[DataRequired()])
    picture = FileField("Picture", render_kw={"class": "form-control", "accept": "image/*"})
    calories = IntegerField("Calories", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    prep_time = IntegerField("Preparation Time (minutes)", validators=[DataRequired(), NumberRange(min=0)], render_kw={"class": "form-control"})
    recipe_type = SelectField("Type", choices=[("Standard", "Standard"), ("Premium", "Premium"), ("Private", "Private")], validators=[DataRequired()], render_kw={"class": "form-control"})
    submit = SubmitField("Create Recipe", render_kw={"class": "btn btn-primary"})


class RecipeSearch(FlaskForm):
    ingredients = StringField("Ingredients", validators=[DataRequired()], render_kw={"class": "form-control"})
    submit = SubmitField("Search", render_kw={"class": "btn btn-primary"})

class AICreateRecipeForm(FlaskForm):
    cuisine = SelectMultipleField('Cuisine', validators=[DataRequired()] ,choices=[("any", "Any"), ("chinese", "Chinese"), ("indian", "Indian"), ("japanese", "Japanese"), ("korean", "Korean"), ("thai", "Thai"), ("western", "Western"), ("french", "French"), ("mediterranean", "Mediterranean") ,("others", "Others")], render_kw={"class": "form-control m-2"})
    # cuisine = BooleanField('Cuisine')
    ingredients = StringField('Ingredients', render_kw={"class": "form-control m-2"})
    # dietary_preference = BooleanField('Dietary Preference', choices=[("nil", "Nil"), ("vegetarian", "Vegetarian"), ("vegan", "Vegan"), ("gluten_free", "Gluten Free"), ("dairy_free", "Dairy Free"), ("nut_free", "Nut Free"), ("others", "Others")], render_kw={"class": "form-control m-2"})

    # allergy = BooleanField('Allergy', choices=[("nil", "Nil"), ("peanut", "Peanut"), ("tree_nut", "Tree Nut"), ("shellfish", "Shellfish"), ("fish", "Fish"), ("soy", "Soy"), ("wheat", "Wheat"), ("dairy", "Dairy"), ("egg", "Egg"), ("others", "Others")], render_kw={"class": "form-control m-2"})

    # meal_type = BooleanField('Meal Type', choices=[("nil", "Nil"), ("breakfast", "Breakfast"), ("lunch", "Lunch"), ("dinner", "Dinner"), ("snack", "Snack"), ("dessert", "Dessert"), ("others", "Others")], render_kw={"class": "form-control m-2"})

    cooking_time = IntegerRangeField('Cooking Time (minutes)', [validators.NumberRange(min=1, max=180)], render_kw={"class": "form-control m-2"})
    difficulty = SelectField('Difficulty', choices=[("easy", "Easy"), ("medium", "Medium"), ("hard", "Hard")], render_kw={"class": "form-control m-2"})
    remarks = TextAreaField('Remarks', render_kw={"class": "form-control m-2"})

class CreateFeedback(FlaskForm):
    name = StringField('Your Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    category = SelectField('Category', choices=[("product", "Product"), ("website", "Website"), ("delivery", "Delivery"), ("others", "Others")])
    rating = DecimalField('Overall Satisfaction', [validators.NumberRange(min=1, max=5)])
    comment = TextAreaField('Feedback', [validators.DataRequired()])


# Order form to order menu items
class MenuForm(FlaskForm):
    menu_item_id = HiddenField()
    submit = SubmitField("Order")


class OrderForm(FlaskForm):
    menu_item_id = HiddenField()
    name = StringField('Name', [Length(min=1, max=150), DataRequired()], render_kw={"placeholder": "John Doe"})
    address = StringField('Address', [Length(min=1, max=150), DataRequired()], render_kw={"placeholder": "123 ABC Street"})
    postal_code = StringField('Postal Code', [six_digit_postal_code_validator, DataRequired()], render_kw={"placeholder": "123456"})
    phone_number = StringField('Phone', [phone_number_validator, DataRequired()], render_kw={"placeholder": "9123 4567"})
    selected_date = DateField('Delivery Date', [validators.DataRequired()], format='%Y-%m-%d')
    selected_time = TimeField('Delivery Time', [validators.DataRequired()], format='%H:%M')
    selected_items = StringField('Selected Items', [validators.DataRequired()])
    submit = SubmitField('Schedule Delivery')
