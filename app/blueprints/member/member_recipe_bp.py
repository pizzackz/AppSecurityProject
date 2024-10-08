from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    flash,
    url_for,
    jsonify,
    abort,
    make_response
)
import re
import imghdr
from app.models import Recipe, RecipeConfig
import os
from sqlalchemy import or_, and_, case
from flask_login import current_user, login_required
from app import limiter
from ...utils import scan_file_with_virustotal, decode_non_whitelisted_tags, log_trans
from hashlib import sha256
from app.forms.forms import CreateRecipeFormMember, RecipeSearch, AICreateRecipeForm, CustomiseRecipeForm
from app import db
from bs4 import BeautifulSoup
import google.generativeai as genai
from datetime import datetime
from flask_jwt_extended import jwt_required, create_access_token, set_access_cookies
# import random
# import sys
# import requests
# import html

member_recipe_bp = Blueprint("member_recipe_bp", __name__)

genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
model = genai.GenerativeModel('gemini-1.5-flash')

def is_image(filename):
    # Check if the file is an image
    image_type = imghdr.what(filename)
    if image_type is not None:
        return True, image_type
    else:
        return False, None

# Recipe Pages
@member_recipe_bp.route("/recipe_database", methods=["GET", "POST"])
@login_required
def recipe_database():
    if current_user.type == 'admin':
        return redirect(url_for('admin_recipe_bp.recipe_database'))
    print(db)  # Checking Database Status
    form = RecipeSearch()

    # Getting pages (For Pagination)
    page = request.args.get('page', 1, type=int)
    per_page = 16
    start = (page - 1) * per_page
    end = start + per_page

    if request.method == 'POST':
        if not form.validate_on_submit():
            print('Failed')
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('member_recipe_bp.recipe_database'))
        else:
            print('Success')
            ingredients = form.ingredients.data
            try:
                ingredients = ingredients.split(',')
            except:
                flash('Error processing ingredients', 'error')
                return redirect(url_for('member_recipe_bp.recipe_database'))

            # Clean data
            if ingredients == []:  # If empty, redirect
                flash('Ingredients are empty!', 'error')
                return redirect(url_for('member_recipe_bp.recipe_database'))
                # return redirect

            # If not pass regex, redirect
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            for i in range(len(ingredients)):
                ingredients[i] = (ingredients[i]).strip()
                if ingredients[i] == '':
                    flash('Ingredients are empty!', 'error')
                    return redirect(url_for('member_recipe_bp.recipe_database'))
                if not re.fullmatch(regex, ingredients[i]):
                    flash('Only letters and spaces allowed', 'error')
                    return redirect(url_for('member_recipe_bp.recipe_database'))
                if len(ingredients[i]) > 20:
                    flash('Ingredient cannot be more than 20 characters', 'error')
                    return redirect(url_for('member_recipe_bp.recipe_database'))
                ingredients[i] = (ingredients[i]).lower()

            # Searching
            search_results = []

            for i in ingredients:
                print(i)
                all_recipes = Recipe.query.filter(
                    or_(
                        Recipe.ingredients.contains(i),
                        Recipe.name.contains(i)
                    ),
                    and_(
                        or_(
                            Recipe.type == 'Standard',
                            Recipe.type == 'Premium',
                            and_(
                                Recipe.type == 'Private',
                                Recipe.user_created_id == current_user.id
                            )
                        )
                    )
                ).all()
                for recipe in all_recipes:
                    if recipe not in search_results:
                        search_results.append(recipe)

            # Sort the search results by the ingredients matched count
            search_results = sorted(search_results,
                                    key=lambda x: len(set(x.ingredients.split(',')).intersection(ingredients)),
                                    reverse=True)
            match = []
            for i in search_results:
                count = 0
                for c in ingredients:
                    print(i.ingredients)
                    print(i.name)
                    if c in i.ingredients:
                        count += 1
                    if c in i.name:
                        count += 1
                match.append(count)
            print(match)

            total_pages = (len(search_results) // per_page) + 1
            search_results = search_results[start:end]

            return render_template("member/recipe/recipe_database.html", form=form, recipes=search_results,
                                   total_pages=total_pages, page=page)

    # Get pages
    total_pages = (Recipe.query.count() // per_page) + 1
    print(f'Total pages: {total_pages}')
    print(f'There are {Recipe.query.count()} recipe')

    items_on_page = Recipe.query.filter(
        or_(
            Recipe.type == 'Standard',
            Recipe.type == 'Premium',
            and_(
                Recipe.type == 'Private',
                Recipe.user_created_id == current_user.id
            )
        )
    ).order_by(
        case(
            (Recipe.type == 'Private', 0),  # Ensure 'Private' recipes appear first
            else_=1
        )
    ).slice(start, end).all()

    return render_template("member/recipe/recipe_database.html", form=form, recipes=items_on_page,
                           total_pages=total_pages, page=page)

@member_recipe_bp.route('/create_recipe', methods=['GET', 'POST'])
@login_required
@limiter.limit('10 per minute')
def create_recipe():
    if current_user.type == 'admin':
        return redirect(url_for('admin_recipe_bp.create_recipe'))
    form = CreateRecipeFormMember()
    if request.method == "POST":
        try:
            # Try to fetch the row with name 'locked_recipes'
            locked_recipes = RecipeConfig.query.filter_by(name='locked_recipes').first()
        except:
            locked_recipes = RecipeConfig(name='locked_recipes', status='False')
            db.session.add(locked_recipes)
            db.session.commit()
        if not locked_recipes:
            locked_recipes = RecipeConfig(name='locked_recipes', status='False')
            db.session.add(locked_recipes)
            db.session.commit()
        if locked_recipes.status == 'True':
            flash('Action cannot be done at the moment.', 'danger')
            print(locked_recipes.status)
            return redirect(url_for('member_recipe_bp.recipe_database'))
        # Handles invalidated form
        if not form.validate_on_submit():
            print('failed')
            flash('Please fill in all fields', 'danger')

        # Handles validated form
        else:
            name = form.name.data
            ingredients = form.ingredients.data
            instructions = form.instructions.data
            picture = form.picture.data
            calories = form.calories.data
            prep_time = form.prep_time.data
            recipe_type = form.recipe_type.data
            print(name, ingredients, instructions, calories, prep_time, recipe_type)

            # PROCESS NAME
            name = name.strip()
            if name == '':
                flash('Name is empty!', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            if not re.fullmatch(regex, name):
                flash('Only letters and spaces allowed', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            if len(name) > 20:
                flash('Name cannot be more than 20 characters', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))

            # PROCESS INSTRUCTIONS
            instructions = instructions.strip()
            if instructions == '':
                flash('Instructions are empty!', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            if len(instructions) > 1000:
                flash('Instructions cannot be more than 1000 characters', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))

            whitelist = ['b', 'i', 'ul', 'ol', 'li', 'hr', 'p', 'strong', 'em', 'span']
            instructions = decode_non_whitelisted_tags(instructions, whitelist)
            # Parse HTML
            soup = BeautifulSoup(instructions, 'html.parser')

            # Only allow whitelisted tags
            for tag in soup.find_all(True):
                if tag.name not in whitelist:
                    tag.decompose()

            # Remove Attributes from Tag
            for tag in soup.find_all(True):
                if tag.attrs != {'text-decoration': 'underline'}:
                    tag.attrs = {}

            instructions = soup.prettify(formatter='minimal')

            # PROCESS CALORIES
            if type(calories) != int:
                flash('Calories must be an integer', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            if calories < 0:
                flash('Calories cannot be negative', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            if calories > 3000:
                flash('Calories cannot be more than 3000', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))

            # PROCESS PREP TIME
            if type(prep_time) != int:
                flash('Prep time must be an integer', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            if prep_time < 0:
                flash('Prep time cannot be negative', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            if prep_time > 300:
                flash('Prep time cannot be more than 300 minutes', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))

            # PROCESS RECIPE TYPE
            if recipe_type != 'Standard' and recipe_type != 'Private':
                flash('Invalid recipe type', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))

            # PROCESS INGREDIENTS
            ingredients = form.ingredients.data
            try:
                ingredients = ingredients.split(',')
            except:
                flash('Error processing ingredients', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))

            # Clean data
            if ingredients == []:  # If empty, redirect
                flash('Ingredients are empty!', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
                # return redirect
            if len(ingredients) > 15:
                flash('Maximum 15 ingredients allowed', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))

            # If not pass regex, redirect
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            print(ingredients)
            for i in range(len(ingredients)):
                ingredients[i] = (ingredients[i]).strip()
                if ingredients[i] == '':
                    flash('Ingredients are empty!', 'error')
                    return redirect(url_for('member_recipe_bp.create_recipe'))
                if not re.fullmatch(regex, ingredients[i]):
                    print(f'Error here, {ingredients[i]}')
                    flash('Only letters and spaces allowed', 'error')
                    return redirect(url_for('member_recipe_bp.create_recipe'))
                if len(ingredients[i]) > 20:
                    flash('Ingredient cannot be more than 20 characters', 'error')
                    return redirect(url_for('member_recipe_bp.create_recipe'))
                ingredients[i] = (ingredients[i]).lower()
            ingredient_cleaned = ''

            for c in range(len(ingredients)):
                ingredient_cleaned += ingredients[c]
                if c != len(ingredients) - 1:
                    ingredient_cleaned += ','

            print(ingredient_cleaned)

            # PROCESS IMAGE
            if picture.filename == '':
                flash('No image uploaded', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            if not is_image(picture):
                flash('Invalid image format', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            picture2 = picture
            scan_result = scan_file_with_virustotal(picture, os.getenv('VIRUSTOTAL_API_KEY'))
            if 'data' in scan_result and scan_result['data'].get('attributes', {}).get('last_analysis_stats', {}).get(
                    'malicious', 0) > 0:
                flash('The uploaded file is potentially malicious and has not been saved.', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))

            # Save the image file
            picture_filename = picture2.filename
            picture_filename = picture_filename.split('.')
            if len(picture_filename) != 2:
                flash('Invalid image format', 'error')
                return redirect(url_for('member_recipe_bp.create_recipe'))
            picture_name = sha256(name.encode()).hexdigest()
            picture_filename = picture_name + '.' + picture_filename[1]

            picture2.stream.seek(0)
            picture2.save(os.path.join('app/static/images_recipe', picture_filename))

            # Store in database
            new_recipe = Recipe(name=name, ingredients=ingredient_cleaned, instructions=instructions,
                                picture=picture_filename, type=recipe_type, calories=calories, prep_time=prep_time,
                                user_created=current_user.username, user_created_id= current_user.id)
            try:
                db.session.add(new_recipe)
                db.session.commit()
                log_trans('Info', 'general', current_user.id, f'Created {name} recipe')
            except:
                print('Error in creating recipe:')
                flash('An error occurred while creating the recipe. Please try again.', 'danger')
            print('Success')
            return redirect(url_for('member_recipe_bp.recipe_database'))
    return render_template('member/recipe/recipe_create.html', form=form)


@member_recipe_bp.route('/view_recipe/<recipe_id>', methods=['GET', 'POST'])
@login_required
def view_recipe(recipe_id):
    if current_user.type == 'admin':
        return redirect(url_for('admin_recipe_bp.view_recipe', recipe_id=recipe_id))
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    if recipe == None:
        abort(404)
    try:
        user_type = current_user.type
        if recipe.type == 'Private' and recipe.user_created_id != current_user.id:
            flash('Action cannot be done', 'error')
            return redirect(url_for('member_recipe_bp.recipe_database'))
        if recipe.type == 'Premium' and current_user.subscription_plan != 'premium':
            flash('Action cannot be done', 'error')
            return redirect(url_for('member_recipe_bp.recipe_database'))
        recipe_data = {
            'id': recipe.id,
            'name': recipe.name,
            'ingredients': (recipe.ingredients).split(','),  # Convert JSON string to Python object
            'instructions': recipe.instructions,
            'picture': recipe.picture,
            'date_created': recipe.date_created,
            'user_created': recipe.user_created,
            'type': recipe.type,
            'calories': recipe.calories,
            'prep_time': recipe.prep_time,
            'ingredient_count': len(recipe.ingredients.split(',')),
        }
    except AttributeError:
        if recipe.type == 'Private' or recipe.type == 'Premium':
            flash('Action cannot be done', 'error')
            return redirect(url_for('member_recipe_bp.recipe_database'))
        recipe_data = {
            'id': recipe.id,
            'name': recipe.name,
            'ingredients': (recipe.ingredients).split(','),  # Convert JSON string to Python object
            'instructions': recipe.instructions,
            'picture': recipe.picture,
            'date_created': recipe.date_created,
            'user_created': recipe.user_created,
            'type': recipe.type,
            'calories': recipe.calories,
            'prep_time': recipe.prep_time,
            'ingredient_count': len(recipe.ingredients.split(',')),
        }
    return render_template('member/recipe/recipe_view2.html', recipe=recipe_data)


@member_recipe_bp.route('/delete_recipe/<recipe_id>', methods=['GET', 'POST'])
@login_required
def delete_recipe(recipe_id):
    if current_user.type == 'admin':
        return redirect(url_for('admin_recipe_bp.delete_recipe', recipe_id=recipe_id))
    try:
        # Try to fetch the row with name 'locked_recipes'
        locked_recipes = RecipeConfig.query.filter_by(name='locked_recipes').first()
    except:
        locked_recipes = RecipeConfig(name='locked_recipes', status='False')
        db.session.add(locked_recipes)
        db.session.commit()
    if not locked_recipes:
        locked_recipes = RecipeConfig(name='locked_recipes', status='False')
        db.session.add(locked_recipes)
        db.session.commit()
    if locked_recipes.status == 'True':
        flash('Action cannot be done at the moment.', 'danger')
        print(locked_recipes.status)
        return redirect(url_for('member_recipe_bp.recipe_database'))
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    recipe_name = recipe.name
    if recipe.type == 'Private' and recipe.user_created_id != current_user.id:
        flash('Action cannot be done', 'error')
        return redirect(url_for('member_recipe_bp.recipe_database'))
    if recipe.type == 'Premium':
        flash('Action cannot be done', 'error')
        return redirect(url_for('member_recipe_bp.recipe_database'))
    flash(f'{recipe.name} was deleted', 'info')
    db.session.delete(recipe)
    db.session.commit()
    log_trans('Info', 'general', current_user.id, f'Deleted {recipe_name} recipe')
    return redirect(url_for('member_recipe_bp.recipe_database'))


@member_recipe_bp.route('/update_recipe/<recipe_id>', methods=['GET', 'POST'])
@login_required
def update_recipe(recipe_id):
    if current_user.type == 'admin':
        return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    if recipe == None:
        abort(404)
    if recipe.type == 'Private' and recipe.user_created_id != current_user.id:
        flash('Action cannot be done', 'error')
        return redirect(url_for('member_recipe_bp.recipe_database'))
    if recipe.type == 'Premium':
        flash('Action cannot be done', 'error')
        return redirect(url_for('member_recipe_bp.recipe_database'))
    form = CreateRecipeFormMember()
    if request.method == 'POST':
        try:
            # Try to fetch the row with name 'locked_recipes'
            locked_recipes = RecipeConfig.query.filter_by(name='locked_recipes').first()
        except:
            locked_recipes = RecipeConfig(name='locked_recipes', status='False')
            db.session.add(locked_recipes)
            db.session.commit()
        if not locked_recipes:
            locked_recipes = RecipeConfig(name='locked_recipes', status='False')
            db.session.add(locked_recipes)
            db.session.commit()
        if locked_recipes.status == 'True':
            flash('Action cannot be done at the moment.', 'danger')
            print(locked_recipes.status)
            return redirect(url_for('member_recipe_bp.recipe_database'))
        name = form.name.data
        ingredients = form.ingredients.data
        instructions = form.instructions.data
        picture = form.picture.data
        calories = form.calories.data
        prep_time = form.prep_time.data
        recipe_type = form.recipe_type.data

        if name != '':
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            if not re.fullmatch(regex, name):
                flash('Only letters and spaces allowed', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            if len(name) > 20:
                flash('Name cannot be more than 20 characters', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))

        if instructions != '':
            instructions = instructions.strip()
            if instructions == '':
                flash('Instructions are empty!', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            if len(instructions) > 1000:
                flash('Instructions cannot be more than 1000 characters', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            print(instructions)
            # Parse HTML
            whitelist = ['b', 'i', 'ul', 'ol', 'li', 'hr', 'p', 'strong', 'em', 'span']
            instructions = decode_non_whitelisted_tags(instructions, whitelist)
            soup = BeautifulSoup(instructions, 'html.parser')

            # Only allow whitelisted tags
            for tag in soup.find_all(True):
                if tag.name not in whitelist:
                    tag.decompose()

            # Remove Attributes from Tag
            for tag in soup.find_all(True):
                if tag.attrs != {'text-decoration': 'underline'}:
                    tag.attrs = {}

            instructions = soup.prettify(formatter='minimal')

        # PROCESS CALORIES
        if calories != '':
            if type(calories) != int:
                flash('Calories must be an integer', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            if calories < 0:
                flash('Calories cannot be negative', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            if calories > 3000:
                flash('Calories cannot be more than 3000', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))

        # PROCESS PREP TIME
        if prep_time != '':
            if type(prep_time) != int:
                flash('Prep time must be an integer', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            if prep_time < 0:
                flash('Prep time cannot be negative', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            if prep_time > 300:
                flash('Prep time cannot be more than 300 minutes', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))

        # PROCESS RECIPE TYPE
        if recipe_type != 'Standard' and recipe_type != 'Private':
            flash('Invalid recipe type', 'error')
            return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))

        # PROCESS INGREDIENTS
        try:
            ingredients = ingredients.split(',')
        except:
            flash('Error processing ingredients', 'error')
            return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))

        # Clean data
        if ingredients != []:
            if len(ingredients) > 15:
                flash('Maximum 15 ingredients allowed', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            # If not pass regex, redirect
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            print(ingredients)
            for i in range(len(ingredients)):
                ingredients[i] = (ingredients[i]).strip()
                if ingredients[i] == '':
                    flash('Ingredients are empty!', 'error')
                    return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
                if not re.fullmatch(regex, ingredients[i]):
                    print(f'Error here, {ingredients[i]}')
                    flash('Only letters and spaces allowed', 'error')
                    return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
                if len(ingredients[i]) > 20:
                    flash('Ingredient cannot be more than 20 characters', 'error')
                    return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
                ingredients[i] = (ingredients[i]).lower()
            ingredient_cleaned = ''

            for c in range(len(ingredients)):
                ingredient_cleaned += ingredients[c]
                if c != len(ingredients) - 1:
                    ingredient_cleaned += ','

        # PROCESS IMAGE
        if picture.filename != '':
            if not is_image(picture):
                flash('Invalid image format', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            # Delete old image
            try:
                os.remove(os.path.join('app/static/images_recipe', recipe.picture))
            except:
                print('Error deleting image')
            picture2 = picture
            scan_result = scan_file_with_virustotal(picture, os.getenv('VIRUSTOTAL_API_KEY'))
            if 'data' in scan_result and scan_result['data'].get('attributes', {}).get('last_analysis_stats', {}).get(
                    'malicious', 0) > 0:
                flash('The uploaded file is potentially malicious and has not been saved.', 'error')
                return redirect(url_for('member_recipe_bp.update_recipe', recipe_id=recipe_id))
            picture_filename = picture2.filename
            picture_filename = picture_filename.split('.')
            picture_name = sha256(name.encode()).hexdigest()
            picture_filename = picture_name + '.' + picture_filename[1]
            picture2.stream.seek(0)
            picture.save(os.path.join('app/static/images_recipe', picture_filename))

        if name != '':
            recipe.name = name
            recipe.date_created = datetime.utcnow()
        if ingredients != []:
            recipe.ingredients = ingredient_cleaned
            recipe.date_created = datetime.utcnow()
        if instructions != '':
            recipe.instructions = soup.prettify()
            recipe.date_created = datetime.utcnow()
        if picture.filename != '':
            recipe.picture = picture_filename
            recipe.date_created = datetime.utcnow()
        if calories != '':
            recipe.calories = calories
            recipe.date_created = datetime.utcnow()
        if prep_time != '':
            recipe.prep_time = prep_time
            recipe.date_created = datetime.utcnow()
        if recipe.type != recipe_type:
            recipe.type = recipe_type
            recipe.date_created = datetime.utcnow()

        db.session.commit()
        log_trans('Info', 'general', current_user.id, f'Updated {name} recipe')
        flash(f'{recipe.name} updated', 'info')
        return redirect(url_for('member_recipe_bp.recipe_database'))

    form.name.data = recipe.name

    form.instructions.data = recipe.instructions
    form.calories.data = recipe.calories
    form.prep_time.data = recipe.prep_time
    form.recipe_type.data = recipe.type
    ingredients = (recipe.ingredients).split(',')

    return render_template('member/recipe/recipe_update.html', form=form, ingredients=ingredients)

@member_recipe_bp.route('/ai_recipe_creator', methods=['GET', 'POST'])
@login_required
def ai_recipe_creator():
    if current_user.type == 'admin':
        return redirect(url_for('admin_recipe_bp.ai_recipe_creator'))
    form = AICreateRecipeForm()
    identity = {'username': current_user.username, 'user_id': current_user.id}
    token = create_access_token(identity=identity)
    response = make_response(render_template('member/recipe/recipe_ai_creator.html', form=form))
    set_access_cookies(response, token)
    return response

@member_recipe_bp.route('/api/recipe-creator-ai', methods=['POST'])
@limiter.limit('10 per minute')
@limiter.limit('100 per hour')
@login_required
@jwt_required()
def recipe_creator_ai():
    print(request.referrer)
    if request.referrer[request.referrer.rfind('/'):] != '/ai_recipe_creator':
        return jsonify({"content": "Invalid request"})
    if current_user == None:
        return jsonify({"content": "Invalid request"})
    # Get user inputs from json data
    print('AI Recipe Creator Activating')
    cuisine = request.json.get('cuisine')
    ingredients = request.json.get('ingredients')
    dietary_preference = request.json.get('dietary_preference')
    allergy = request.json.get('allergy')
    meal_type = request.json.get('meal_type')
    difficulty = request.json.get('difficulty')
    remarks = request.json.get('remarks')

    # Clean Inputs
    regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
    regex2 = r'^[a-zA-Z, ]+$'

    cuisine = cuisine.strip()
    if cuisine != '':
        if len(cuisine) > 12:
            return jsonify({'content': 'Cuisine is too long. Please keep within 12 characters'})
        if not re.fullmatch(regex, cuisine):
            return jsonify({'content':'Only letters and spaces allowed in cuisine'})

    ingredients = ingredients.strip()
    if ingredients != '':
        if len(ingredients) > 30:
            return jsonify({'content': 'Ingredients are too long. Please keep within 30 characters'})
        if not re.fullmatch(regex2, ingredients):
            return jsonify({'content':'Only letters, spaces and commas allowed in ingredients'})

    dietary_preference = dietary_preference.strip()
    if dietary_preference != '':
        if len(dietary_preference) > 15:
            return jsonify({'content': 'Dietary preference is too long. Please keep within 15 characters'})
        if not re.fullmatch(regex, dietary_preference):
            return jsonify({'content':'Only letters and spaces allowed in dietary preference'})

    allergy = allergy.strip()
    if allergy != '':
        if len(allergy) > 15:
            return jsonify({'content': 'Allergy is too long. Please keep within 15 characters'})
        if not re.fullmatch(regex, allergy):
            return jsonify({'content':'Only letters and spaces allowed in allergy'})

    meal_type = meal_type.strip()
    if meal_type != '':
        if len(meal_type) > 15:
            return jsonify({'content': 'Meal type is too long. Please keep within 15 characters'})
        if not re.fullmatch(regex, meal_type):
            return jsonify({'content':'Only letters and spaces allowed in meal type'})

    difficulty = difficulty.strip()
    if difficulty not in ['easy', 'medium', 'hard', 'any']:
        return jsonify({'content':'Please try again.'})

    remarks = remarks.strip()
    if remarks != '':
        if len(remarks) > 70:
            return jsonify({'content': 'Remarks is too long. Please keep within 70 characters'})
        if not re.fullmatch(regex2, remarks):
            return jsonify({'content':'Only letters, spaces and commas allowed in remarks'})

    messages = ''
    messages += """You are a recipe creator.
                       Ignore all unrelated inputs, and only output recipe in 
                       the following format: Name, ingredients, description (Put in the other details 
                       inside like calories, and other things the user specifies), and instructions. 
                       Do not put #, * or any other special symbols."""

    messages += f'''You are creating a recipe for {cuisine} cuisine. 
                    Ensure {ingredients} are in the recipe. The dietary preference is
                    {dietary_preference}. The allergies are {allergy}. The meal type is {meal_type}.
                    The difficulty is {difficulty}.
                    Remarks are (Ignore this part if irrelevant) {remarks}'''

    print(messages)
    response = model.generate_content(messages)
    cleaned = response.text
    cleaned = cleaned.replace("## ", "")
    cleaned = cleaned.replace("**", "")
    cleaned = cleaned.replace("* ", "- ")

    log_trans('Info', 'general', current_user.id, f'Made a request to recipe-creator-ai')
    return jsonify({'content': cleaned})

@member_recipe_bp.route('/customise_recipe/<recipe_id>')
@login_required
def customise_recipe(recipe_id):
    if current_user.type == 'admin':
        return redirect(url_for('admin_recipe_bp.customise_recipe', recipe_id=recipe_id))
    form = CustomiseRecipeForm()
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    if recipe.type == 'Private' and recipe.user_created_id != current_user.id:
        flash('Action cannot be done', 'error')
        return redirect(url_for('member_recipe_bp.recipe_database'))
    if recipe.type == 'Premium' and current_user.subscription_plan != 'premium':
        flash('Action cannot be done', 'error')
        return redirect(url_for('member_recipe_bp.recipe_database'))
    if recipe == None:
        abort(404)
    identity = {'username': current_user.username, 'user_id': current_user.id}
    token = create_access_token(identity=identity)
    response = make_response(render_template('member/recipe/recipe_customise.html', recipe=recipe, form=form))
    set_access_cookies(response, token)
    return response

@member_recipe_bp.route('/api/recipe-customise-ai', methods=['POST'])
@limiter.limit('10 per minute')
@limiter.limit('100 per hour')
@login_required
@jwt_required()
def recipe_customise_ai():
    referrer_link = (request.referrer).split('/')
    if referrer_link[-2] != 'customise_recipe':
        return jsonify({"content": "Invalid request"})
    try:
        recipe_id = int(referrer_link[-1])
    except:
        return jsonify({"content": "Invalid request"})
    user_request = request.json.get('request')
    regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    if recipe == None:
        return jsonify({'content': 'Invalid Request'})
    if current_user.type != 'admin':
        if recipe.type == 'Private' and recipe.user_created_id != current_user.id:
            return jsonify({'content', 'Unauthorized action'})
        if recipe.type == 'Premium' and current_user.subscription_plan != 'premium':
            return jsonify({'content', 'Unauthorized action'})
    if user_request == '':
        return jsonify({'content': 'Please enter a request'})
    user_request = user_request.strip()
    if len(user_request) > 100:
        return jsonify({'content': 'Request is too long. Please keep within 100 characters'})
    if not re.fullmatch(regex, user_request):
        return jsonify({'content':'Only letters and spaces allowed in request'})
    message = f"""
    You are a recipe customiser. The recipe below is the current recipe that you are customising:
    Name: {recipe.name}
    Ingredients: {recipe.ingredients}
    Instructions: {recipe.instructions} (Ignore the HTML Tags)
    Calories: {recipe.calories}
    Preparation Time: {recipe.prep_time}.
    Now you are to edit the recipe according to the user's request. Ignore the user's request if it is irrelevant. Put it in the same format (name, ingredients, instructions, calories
    preparation time. Do not put #, * or any other special symbols. The user's request is as follows: {user_request}
    """
    response = model.generate_content(message)
    cleaned = response.text
    cleaned = cleaned.replace("## ", "")
    cleaned = cleaned.replace("**", "")
    cleaned = cleaned.replace("* ", "- ")

    log_trans('Info', 'general', current_user.id, f'Made a request to recipe-customise-ai')
    return jsonify({'content': cleaned})
