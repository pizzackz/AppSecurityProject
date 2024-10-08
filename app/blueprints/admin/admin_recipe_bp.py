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
from app.models import Recipe, RecipeDeleted, RecipeConfig
import os
from sqlalchemy import or_, and_
from app.populate_recipes import populate_recipes
from hashlib import sha256
from ...utils import scan_file_with_virustotal, decode_non_whitelisted_tags, log_trans
from flask_login import current_user

from datetime import datetime, timedelta
from app.forms.forms import CreateRecipeForm, RecipeSearch, AICreateRecipeForm, CustomiseRecipeForm
from app import db
from bs4 import BeautifulSoup
from flask_jwt_extended import jwt_required, create_access_token, set_access_cookies
import google.generativeai as genai
from flask_login import login_required
import html

# import json
# from PIL import Image
# import flask_sqlalchemy
# from app.models import Recipe
# from werkzeug.utils import secure_filename
# from werkzeug.security import generate_password_hash, check_password_hash


admin_recipe_bp = Blueprint("admin_recipe_bp", __name__)

# Google Gemini API Setup
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
@admin_recipe_bp.route("/admin/recipe_database", methods=["GET", "POST"])
@login_required
def recipe_database():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401

    print(db) # Checking Database Status
    form = RecipeSearch()

    # Getting pages (For Pagination)
    page = request.args.get('page', 1, type=int)
    per_page = 16

    if request.method == 'POST':
        if not form.validate_on_submit():
            print('Failed')
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('admin_recipe_bp.recipe_database'))
        else:
            print('Success')
            ingredients = form.ingredients.data
            try:
                ingredients = ingredients.split(',')
            except:
                flash('Error processing ingredients', 'error')
                return redirect(url_for('admin_recipe_bp.recipe_database'))

            # Clean data
            if ingredients == []:  # If empty, redirect
                flash('Ingredients are empty!', 'error')
                return redirect(url_for('admin_recipe_bp.recipe_database'))
                # return redirect

            if len(ingredients) > 12:
                flash('Max ingredients is 12!', 'error')
                return redirect(url_for('admin_recipe_bp.recipe_database'))

            # If not pass regex, redirect
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            for i in range(len(ingredients)):
                ingredients[i] = (ingredients[i]).strip()
                if ingredients[i] == '':
                    flash('Ingredients are empty!', 'error')
                    return redirect(url_for('admin_recipe_bp.recipe_database'))
                if not re.fullmatch(regex, ingredients[i]):
                    flash('Only letters and spaces allowed', 'error')
                    return redirect(url_for('admin_recipe_bp.recipe_database'))
                if len(ingredients[i]) > 20:
                    flash('Ingredient cannot be more than 20 characters', 'error')
                    return redirect(url_for('admin_recipe_bp.recipe_database'))
                ingredients[i] = (ingredients[i]).lower()

            # Searching
            search_results = []

            print(ingredients)
            for i in ingredients:
                print(i)
                all_recipes = Recipe.query.filter(
                    or_(
                        Recipe.ingredients.contains(i),
                        Recipe.name.contains(i)
                    )
                ).all()
                for recipe in all_recipes:
                    if recipe not in search_results:
                        search_results.append(recipe)

            # Sort the search results by the ingredients matched count
            search_results = sorted(search_results, key=lambda x: len(set(x.ingredients.split(',')).intersection(ingredients)), reverse=True)
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

            # Pagination for POST
            start = (page - 1) * per_page
            end = start + per_page
            search_results = search_results[start:end]
            total_pages = (len(search_results) // per_page) + 1

            return render_template("admin/recipe/recipe_database.html", form=form, recipes=search_results, total_pages=total_pages, page=page)

    # Get pages
    total_pages = (Recipe.query.count() // per_page) + 1
    print(f'Total pages: {total_pages}')
    print(f'There are {Recipe.query.count()} recipe')

    items_on_page = Recipe.query.order_by(db.case((Recipe.type == 'private', 0),else_=1)).paginate(page=page, per_page=per_page)

    return render_template("admin/recipe/recipe_database.html", form=form, recipes=items_on_page, total_pages=total_pages, page=page)


@admin_recipe_bp.route('/admin/create_recipe', methods=['GET', 'POST'])
@login_required
def create_recipe():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    form = CreateRecipeForm()
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
            flash('Action cannot be done at the moment.', 'error')
            return redirect(url_for('admin_recipe_bp.create_recipe'))
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
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            if not re.fullmatch(regex, name):
                flash('Only letters and spaces allowed', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            if len(name) > 20:
                flash('Name cannot be more than 20 characters', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            existing_recipe_in_database = Recipe.query.filter(Recipe.name == name).first()
            if existing_recipe_in_database:
                flash(f'{name} exists in database', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))

            # PROCESS INSTRUCTIONS
            instructions = instructions.strip()
            if instructions == '':
                flash('Instructions are empty!', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            if len(instructions) > 1000:
                flash('Instructions cannot be more than 1000 characters', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            # Only allow whitelist tags
            whitelist = ['b', 'i', 'ul', 'ol', 'li', 'hr', 'p', 'strong', 'em', 'span']
            instructions = decode_non_whitelisted_tags(instructions, whitelist)

            # Parse HTML
            soup = BeautifulSoup(instructions, 'html.parser')

            # Only allow whitelisted tags
            for tag in soup.find_all():
                print(tag)
                if tag.name not in whitelist:
                    tag.decompose()

            # Remove Attributes from Tag
            for tag in soup.find_all(True):
                if tag.attrs != {'text-decoration': 'underline'}:
                    tag.attrs = {}

            instructions = soup.prettify(formatter='minimal')
            print(instructions)

            # PROCESS CALORIES
            if type(calories) != int:
                flash('Calories must be an integer', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            if calories < 0:
                flash('Calories cannot be negative', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            if calories > 3000:
                flash('Calories cannot be more than 3000', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))

            # PROCESS PREP TIME
            if type(prep_time) != int:
                flash('Prep time must be an integer', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            if prep_time < 0:
                flash('Prep time cannot be negative', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            if prep_time > 300:
                flash('Prep time cannot be more than 300 minutes', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))

            # PROCESS RECIPE TYPE
            if recipe_type != 'Standard' and recipe_type != 'Premium' and recipe_type != 'Private':
                flash('Invalid recipe type', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))

            # PROCESS INGREDIENTS
            ingredients = form.ingredients.data
            try:
                ingredients = ingredients.split(',')
            except:
                flash('Error processing ingredients', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))

            # Clean data
            if ingredients == []:  # If empty, redirect
                flash('Ingredients are empty!', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
                # return redirect

            # If not pass regex, redirect
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            print(ingredients)
            if len(ingredients) > 15:
                flash('Maximum 15 ingredients allowed', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            for i in range(len(ingredients)):
                ingredients[i] = (ingredients[i]).strip()
                if ingredients[i] == '':
                    flash('Ingredients are empty!', 'error')
                    return redirect(url_for('admin_recipe_bp.create_recipe'))
                if not re.fullmatch(regex, ingredients[i]):
                    print(f'Error here, {ingredients[i]}')
                    flash('Only letters and spaces allowed', 'error')
                    return redirect(url_for('admin_recipe_bp.create_recipe'))
                if len(ingredients[i]) > 20:
                    flash('Ingredient cannot be more than 20 characters', 'error')
                    return redirect(url_for('admin_recipe_bp.create_recipe'))
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
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            if not is_image(picture):
                flash('Invalid image format', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))

            picture2 = picture
            scan_result = scan_file_with_virustotal(picture, os.getenv('VIRUSTOTAL_API_KEY'))
            if 'data' in scan_result and scan_result['data'].get('attributes', {}).get('last_analysis_stats', {}).get(
                    'malicious', 0) > 0:
                flash('The uploaded file is potentially malicious and has not been saved.', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            # if not is_square_image(picture):
            #     flash('Image size must be 1:1', 'error')
            #     return redirect(url_for('admin_recipe_bp.create_recipe'))

            # Save the image file
            picture_filename = picture2.filename
            picture_filename = picture_filename.split('.')
            if len(picture_filename) != 2:
                flash('Invalid image format', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            picture_name = sha256(name.encode()).hexdigest()
            picture_filename = picture_name + '.' + picture_filename[1]

            picture2.stream.seek(0)
            picture2.save(os.path.join('app/static/images_recipe', picture_filename))

            # Store in database
            new_recipe = Recipe(name=name, ingredients=ingredient_cleaned, instructions=instructions, picture=picture_filename, type=recipe_type, calories=calories, prep_time=prep_time, user_created=current_user.username, user_created_id=current_user.id)
            try:
                db.session.add(new_recipe)
                db.session.commit()
                log_trans('Info', 'general', current_user.id, f'Created recipe {name}')
            except:
                print('Error in creating recipe:')
                flash('An error occurred while creating the recipe. Please try again.', 'danger')
            print('Success')
            return redirect(url_for('admin_recipe_bp.recipe_database'))
    return render_template('admin/recipe/recipe_create.html', form=form)


@admin_recipe_bp.route('/admin/view_recipe/<recipe_id>', methods=['GET', 'POST'])
@login_required
def view_recipe(recipe_id):
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    if recipe == None:
        abort(404)
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
    return render_template('admin/recipe/recipe_view2.html', recipe=recipe_data)


@admin_recipe_bp.route('/admin/delete_recipe/<recipe_id>', methods=['GET', 'POST'])
@login_required
def delete_recipe(recipe_id):
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
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
        flash('Action cannot be done at the moment.', 'error')
        print(locked_recipes.status)
        return redirect(url_for('admin_recipe_bp.recipe_database'))
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    if recipe == None:
        log_trans('Error', 'general', current_user.id, 'Tried deleting a non-existent recipe')
        return redirect(url_for('admin_recipe_bp.recipe_database'))
    flash(f'{recipe.name} was deleted', 'info')
    recipe_name = recipe.name
    old_recipe = RecipeDeleted(name=recipe.name, ingredients=recipe.ingredients, instructions=recipe.instructions, picture=recipe.picture, type=recipe.type, calories=recipe.calories, prep_time=recipe.prep_time, user_created=recipe.user_created, user_created_id=recipe.user_created_id , date_created=recipe.date_created)
    db.session.add(old_recipe)
    db.session.delete(recipe)
    db.session.commit()
    log_trans('Info', 'general', current_user.id, f'Deleted recipe {recipe_name}')
    return redirect(url_for('admin_recipe_bp.recipe_database'))


@admin_recipe_bp.route('/admin/update_recipe/<recipe_id>', methods=['GET', 'POST'])
@login_required
def update_recipe(recipe_id):
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    if recipe == None:
        abort(404)
    form = CreateRecipeForm()
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
            flash('Action cannot be done at the moment.', 'error')
            return redirect(url_for('admin_recipe_bp.update_recipe'))

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
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
            if len(name) > 20:
                flash('Name cannot be more than 20 characters', 'error')
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
            existing_recipe_in_database = Recipe.query.filter(and_(Recipe.name == name, Recipe.id != recipe_id)).first()
            print(existing_recipe_in_database)
            if existing_recipe_in_database:
                flash(f'{name} exists in database', 'error')
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))

        if instructions != '':
            instructions = instructions.strip()
            if instructions == '':
                flash('Instructions are empty!', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            if len(instructions) > 1000:
                flash('Instructions cannot be more than 1000 characters', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            # Parse HTML
            whitelist = ['b', 'i', 'ul', 'ol', 'li', 'hr', 'p', 'strong', 'em', 'span']
            instructions = decode_non_whitelisted_tags(instructions, whitelist)

            soup = BeautifulSoup(instructions, 'html.parser')
            for tag in soup.find_all(True):
                print('Tag is', tag)
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
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
            if calories < 0:
                flash('Calories cannot be negative', 'error')
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
            if calories > 3000:
                flash('Calories cannot be more than 3000', 'error')
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))

        # PROCESS PREP TIME
        if prep_time != '':
            if type(prep_time) != int:
                flash('Prep time must be an integer', 'error')
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
            if prep_time < 0:
                flash('Prep time cannot be negative', 'error')
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
            if prep_time > 300:
                flash('Prep time cannot be more than 300 minutes', 'error')
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))

        # PROCESS RECIPE TYPE
        if recipe_type != 'Standard' and recipe_type != 'Premium' and recipe_type != 'Private':
            flash('Invalid recipe type', 'error')
            return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))

        # PROCESS INGREDIENTS
        try:
            ingredients = ingredients.split(',')
        except:
            flash('Error processing ingredients', 'error')
            return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))

        # Clean data
        if ingredients != []:
            # If not pass regex, redirect
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            if len(ingredients) > 15:
                flash('Maximum 15 ingredients allowed', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            print(ingredients)
            for i in range(len(ingredients)):
                ingredients[i] = (ingredients[i]).strip()
                if ingredients[i] == '':
                    flash('Ingredients are empty!', 'error')
                    return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
                if not re.fullmatch(regex, ingredients[i]):
                    print(f'Error here, {ingredients[i]}')
                    flash('Only letters and spaces allowed', 'error')
                    return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
                if len(ingredients[i]) > 20:
                    flash('Ingredient cannot be more than 20 characters', 'error')
                    return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
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
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
            picture2 = picture
            scan_result = scan_file_with_virustotal(picture, os.getenv('VIRUSTOTAL_API_KEY'))
            if 'data' in scan_result and scan_result['data'].get('attributes', {}).get('last_analysis_stats', {}).get(
                    'malicious', 0) > 0:
                flash('The uploaded file is potentially malicious and has not been saved.', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            picture_filename = picture2.filename
            picture_filename = picture_filename.split('.')
            if len(picture_filename) != 2:
                flash('Invalid image format', 'error')
                return redirect(url_for('admin_recipe_bp.update_recipe', recipe_id=recipe_id))
            # Delete old image
            try:
                os.remove(os.path.join('app/static/images_recipe', recipe.picture))
            except:
                print('No old picture')
            picture_name = sha256(name.encode()).hexdigest()
            picture_filename = picture_name + '.' + picture_filename[1]
            picture2.stream.seek(0)
            picture2.save(os.path.join('app/static/images_recipe', picture_filename))

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
        log_trans('Info', 'general', current_user.id, f'Deleted recipe {name}')
        flash(f'{recipe.name} updated', 'info')
        return redirect(url_for('admin_recipe_bp.recipe_database'))

    form.name.data = recipe.name
    form.instructions.data = recipe.instructions
    form.calories.data = recipe.calories
    form.prep_time.data = recipe.prep_time
    form.recipe_type.data = recipe.type
    ingredients = (recipe.ingredients).split(',')

    return render_template('admin/recipe/recipe_update.html', form=form, ingredients=ingredients)


@admin_recipe_bp.route('/admin/recipe_dashboard')
@login_required
def recipe_dashboard():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    recipes = Recipe.query.all()

    # sort the recipes by date created
    recipes = sorted(recipes, key=lambda x: x.date_created, reverse=True)
    recipes = recipes[:5]

    deletedrecipes = RecipeDeleted.query.all()
    deletedrecipes = sorted(deletedrecipes, key=lambda x: x.date_deleted, reverse=True)
    deletedrecipes = deletedrecipes[:5]
    data = {
        'recipe_count': Recipe.query.count(),
        'premium_recipe': Recipe.query.filter_by(type='Premium').count(),
        'standard_recipe': Recipe.query.filter_by(type='Standard').count(),
        'private_recipe': Recipe.query.filter_by(type='Private').count()
    }
    try:
        locked_recipe_object = RecipeConfig.query.filter_by(name='locked_recipes').first()
        print(locked_recipe_object)
    except:
        locked_recipe_object = RecipeConfig(name='locked_recipes', status='False')
        db.session.add(locked_recipe_object)
        db.session.commit()
    if not locked_recipe_object:
        locked_recipe_object = RecipeConfig(name='locked_recipes', status='False')
        db.session.add(locked_recipe_object)
        db.session.commit()
    locked_recipes = locked_recipe_object.status
    print(locked_recipes)

    identity = {'username': current_user.username, 'user_id': current_user.id}
    token = create_access_token(identity=identity)
    response = make_response(render_template('admin/recipe/recipe_dashboard.html', recipes=recipes, locked_recipes=locked_recipes, data=data, deletedrecipes=deletedrecipes))
    set_access_cookies(response, token)
    return response


@admin_recipe_bp.route('/api/recipe_info', methods=['GET'])
@login_required
@jwt_required()
def recipe_info():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    if request.referrer[request.referrer.rfind('/'):] != '/recipe_dashboard':
        return jsonify({"message": "Unauthorized"}), 401

    now = datetime.now()
    recipe_count_last_12_hours = []

    # Loop through the last 12 hours
    for i in range(12, 0, -1):
        start_time = now - timedelta(hours=i)
        end_time = now - timedelta(hours=i - 1)
        count = Recipe.query.filter(Recipe.date_created >= start_time, Recipe.date_created < end_time).count()
        recipe_count_last_12_hours.append(count)

    return jsonify({'content':recipe_count_last_12_hours})


@admin_recipe_bp.route('/admin/lock_recipes')
@login_required
def lock_recipes():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    try:
        locked_recipes = RecipeConfig.query.filter_by(name='locked_recipes').first()
    except:
        locked_recipes = RecipeConfig(name='locked_recipes', status='True')
        db.session.add(locked_recipes)
    if not locked_recipes:
        locked_recipes = RecipeConfig(name='locked_recipes', status='True')
        db.session.add(locked_recipes)

    locked_recipes.status = 'True'
    print(locked_recipes.status)
    try:
        db.session.commit()
        log_trans('Info', 'general', current_user.id, f'Locked Recipes')
        flash('Recipes locked', 'info')
    except:
        log_trans('Error', 'general', current_user.id, f'Problem Locking Recipes')
    return redirect(url_for('admin_recipe_bp.recipe_dashboard'))


@admin_recipe_bp.route('/admin/unlock_recipes')
@login_required
def unlock_recipes():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    try:
        locked_recipes = RecipeConfig.query.filter_by(name='locked_recipes').first()
    except:
        locked_recipes = RecipeConfig(name='locked_recipes', status='False')
        db.session.add(locked_recipes)
    if not locked_recipes:
        locked_recipes = RecipeConfig(name='locked_recipes', status='False')
        db.session.add(locked_recipes)
    locked_recipes.status = 'False'
    print(locked_recipes.status)
    try:
        db.session.commit()
        flash('Recipes unlocked', 'info')
        log_trans('Info', 'general', current_user.id, f'Unlocked Recipes')
    except:
        log_trans('Error', 'general', current_user.id, f'Problem Unlocking Recipes')
    return redirect(url_for('admin_recipe_bp.recipe_dashboard'))


@admin_recipe_bp.route('/admin/populate_recipes')
@login_required
def populate_recipes_database():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    try:
        populate_recipes()
        flash('Populated recipe', 'info')
        log_trans('Info', 'general', current_user.id, f'Populated recipes')
    except:
        log_trans('Error', 'general', current_user.id, f'Problem populating recipes')
    return redirect(url_for('admin_recipe_bp.recipe_dashboard'))


@admin_recipe_bp.route('/admin/reset_recipes')
@login_required
def reset_recipes():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    recipes = Recipe.query.all()
    for recipe in recipes:
        old_recipe = RecipeDeleted(name=recipe.name, ingredients=recipe.ingredients, instructions=recipe.instructions,
                                   picture=recipe.picture, type=recipe.type, calories=recipe.calories,
                                   prep_time=recipe.prep_time, user_created=recipe.user_created,
                                   user_created_id=recipe.user_created_id, date_created=recipe.date_created)
        db.session.add(old_recipe)
        db.session.delete(recipe)
        db.session.commit()
    db.session.commit()
    flash('Database reset', 'info')
    log_trans('Info', 'general', current_user.id, f'Cleared all recipes')
    return redirect(url_for('admin_recipe_bp.recipe_dashboard'))


@admin_recipe_bp.route('/admin/reset_deleted_recipes')
@login_required
def reset_deleted_recipes():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    recipes = RecipeDeleted.query.all()
    for recipe in recipes:
        try:
            os.remove(os.path.join('app/static/images_recipe', recipe.picture))
        except:
            print('Picture not found')
        db.session.delete(recipe)
    db.session.commit()
    flash('Deleted Database reset', 'info')
    log_trans('Info', 'general', current_user.id, f'Cleared deleted recipes')
    return redirect(url_for('admin_recipe_bp.recipe_dashboard'))


@admin_recipe_bp.route('/admin/deleted_recipe_database', methods=['GET', 'POST'])
@login_required
def deleted_recipe_database():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    print(db) # Checking Database Status
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
            return redirect(url_for('admin_recipe_bp.recipe_database'))
        else:
            print('Success')
            ingredients = form.ingredients.data
            try:
                ingredients = ingredients.split(',')
            except:
                flash('Error processing ingredients', 'error')
                return redirect(url_for('admin_recipe_bp.recipe_database'))

            # Clean data
            if ingredients == []:  # If empty, redirect
                flash('Ingredients are empty!', 'error')
                return redirect(url_for('admin_recipe_bp.recipe_database'))
                # return redirect

            # If not pass regex, redirect
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            for i in range(len(ingredients)):
                ingredients[i] = (ingredients[i]).strip()
                if ingredients[i] == '':
                    flash('Ingredients are empty!', 'error')
                    return redirect(url_for('admin_recipe_bp.deleted_recipe_database'))
                if not re.fullmatch(regex, ingredients[i]):
                    flash('Only letters and spaces allowed', 'error')
                    return redirect(url_for('admin_recipe_bp.deleted_recipe_database'))
                if len(ingredients[i]) > 20:
                    flash('Ingredient cannot be more than 20 characters', 'error')
                    return redirect(url_for('admin_recipe_bp.deleted_recipe_database'))
                ingredients[i] = (ingredients[i]).lower()

            # Searching
            search_results = []

            print(ingredients)
            for i in ingredients:
                print(i)
                all_recipes = RecipeDeleted.query.filter(
                    or_(
                        Recipe.ingredients.contains(i),
                        Recipe.name.contains(i)
                    )
                ).all()
                for recipe in all_recipes:
                    if recipe not in search_results:
                        search_results.append(recipe)

            # Sort the search results by the ingredients matched count
            search_results = sorted(search_results, key=lambda x: len(set(x.ingredients.split(',')).intersection(ingredients)), reverse=True)
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

            return render_template("admin/recipe/recipe_database_deleted.html", form=form, recipes=search_results, total_pages=total_pages, page=page)

    # Get pages
    total_pages = (RecipeDeleted.query.count() // per_page) + 1
    print(f'Total pages: {total_pages}')
    print(f'There are {RecipeDeleted.query.count()} recipe')

    items_on_page = RecipeDeleted.query.slice(start, end)

    return render_template("admin/recipe/recipe_database_deleted.html", form=form, recipes=items_on_page, total_pages=total_pages, page=page)


# View deleted recipes
@admin_recipe_bp.route('/admin/view_deleted_recipe/<recipe_id>', methods=['GET', 'POST'])
@login_required
def view_deleted_recipe(recipe_id):
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    recipe = RecipeDeleted.query.filter_by(id=recipe_id).first()
    if recipe == None:
        abort(404)
    recipe_data = {
       'id': recipe.id,
       'name': recipe.name,
       'ingredients': (recipe.ingredients).split(','),  # Convert JSON string to Python object
       'instructions': recipe.instructions,
       'picture': recipe.picture,
       'date_created': recipe.date_created,
        'date_deleted':recipe.date_deleted,
       'user_created': recipe.user_created,
       'type': recipe.type,
       'calories': recipe.calories,
       'prep_time': recipe.prep_time,
       'ingredient_count': len(recipe.ingredients.split(',')),
    }
    return render_template('admin/recipe/recipe_view_deleted.html', recipe=recipe_data)


@admin_recipe_bp.route('/admin/delete_recipe_forever/<recipe_id>', methods=['GET', 'POST'])
@login_required
def delete_recipe_forever(recipe_id):
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    recipe = RecipeDeleted.query.filter_by(id=recipe_id).first()
    recipe_name = recipe.name
    try:
        os.remove(os.path.join('app/static/images_recipe', recipe.picture))
    except:
        print('Picture not found')
        log_trans('Error', 'general', current_user.id, f"Problems deleting {recipe_name}'s picture")
    flash(f'{recipe.name} was deleted forever', 'info')
    db.session.delete(recipe)
    db.session.commit()
    log_trans('Info', 'general', current_user.id, f'Deleted {recipe_name} forever')
    return redirect(url_for('admin_recipe_bp.deleted_recipe_database'))


@admin_recipe_bp.route('/admin/restore_recipe/<recipe_id>', methods=['GET', 'POST'])
@login_required
def restore_recipe(recipe_id):
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    recipe = RecipeDeleted.query.filter_by(id=recipe_id).first()
    recipe_name = recipe.name
    flash(f'{recipe.name} was restored', 'info')
    new_recipe = Recipe(name=recipe.name, ingredients=recipe.ingredients, instructions=recipe.instructions, picture=recipe.picture, type=recipe.type, calories=recipe.calories, prep_time=recipe.prep_time, user_created=recipe.user_created, user_created_id=recipe.user_created_id , date_created=recipe.date_created)
    db.session.add(new_recipe)
    db.session.delete(recipe)
    db.session.commit()
    log_trans('Info', 'general', current_user.id, f'Restored {recipe_name} recipe')
    return redirect(url_for('admin_recipe_bp.recipe_database'))


@admin_recipe_bp.route('/admin/ai_recipe_creator', methods=['GET'])
@login_required
def ai_recipe_creator():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    form = AICreateRecipeForm()
    identity = {'username': current_user.username, 'user_id': current_user.id}
    token = create_access_token(identity=identity)
    response = make_response(render_template('admin/recipe/recipe_ai_creator.html', form=form))
    set_access_cookies(response, token)
    return response


@admin_recipe_bp.route('/admin/customise_recipe/<recipe_id>')
@login_required
def customise_recipe(recipe_id):
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    form = CustomiseRecipeForm()
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    if recipe == None:
        abort(404)
    identity = {'username': current_user.username, 'user_id': current_user.id}
    token = create_access_token(identity=identity)
    response = make_response(render_template('admin/recipe/recipe_customise.html', recipe=recipe, form=form))
    set_access_cookies(response, token)
    return response





# @admin_recipe_bp.route('/api/recipe-creator-ai', methods=['POST'])
# @login_required
# # @jwt_required()
# @limiter.limit('10 per minute')
# @limiter.limit('100 per hour')
# def recipe_creator_ai():
#     # Get user inputs from json data
#     print('AI Recipe Creator Activating')
#     cuisine = request.json.get('cuisine')
#     ingredients = request.json.get('ingredients')
#     dietary_preference = request.json.get('dietary_preference')
#     allergy = request.json.get('allergy')
#     meal_type = request.json.get('meal_type')
#     difficulty = request.json.get('difficulty')
#     print(difficulty)
#     remarks = request.json.get('remarks')
#
#     # Clean Inputs
#     regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
#     regex2 = r'^[a-zA-Z, ]+$'
#
#     cuisine = cuisine.strip()
#     if cuisine != '':
#         if len(cuisine) > 12:
#             return jsonify({'content': 'Cuisine is too long. Please keep within 12 characters'})
#         if not re.fullmatch(regex, cuisine):
#             return jsonify({'content':'Only letters and spaces allowed in cuisine'})
#
#     ingredients = ingredients.strip()
#     if ingredients != '':
#         if len(ingredients) > 30:
#             return jsonify({'content': 'Ingredients are too long. Please keep within 30 characters'})
#         if not re.fullmatch(regex2, ingredients):
#             return jsonify({'content':'Only letters, spaces and commas allowed in ingredients'})
#
#     dietary_preference = dietary_preference.strip()
#     if dietary_preference != '':
#         if len(dietary_preference) > 15:
#             return jsonify({'content': 'Dietary preference is too long. Please keep within 15 characters'})
#         if not re.fullmatch(regex, dietary_preference):
#             return jsonify({'content':'Only letters and spaces allowed in dietary preference'})
#
#     allergy = allergy.strip()
#     if allergy != '':
#         if len(allergy) > 15:
#             return jsonify({'content': 'Allergy is too long. Please keep within 15 characters'})
#         if not re.fullmatch(regex, allergy):
#             return jsonify({'content':'Only letters and spaces allowed in allergy'})
#
#     meal_type = meal_type.strip()
#     if meal_type != '':
#         if len(meal_type) > 15:
#             return jsonify({'content': 'Meal type is too long. Please keep within 15 characters'})
#         if not re.fullmatch(regex, meal_type):
#             return jsonify({'content':'Only letters and spaces allowed in meal type'})
#
#     difficulty = difficulty.strip()
#     if difficulty not in ['easy', 'medium', 'hard', 'any']:
#         return jsonify({'content':'Please try again.'})
#
#     remarks = remarks.strip()
#     if remarks != '':
#         if len(remarks) > 30:
#             return jsonify({'content': 'Remarks is too long. Please keep within 30 characters'})
#         if not re.fullmatch(regex2, remarks):
#             return jsonify({'content':'Only letters, spaces and commas allowed in remarks'})
#
#     messages = ''
#     messages += """You are a recipe creator.
#                        Ignore all unrelated inputs, and only output recipe in
#                        the following format: Name, ingredients, description (Put in the other details
#                        inside like calories, and other things the user specifies), and instructions.
#                        Do not put #, * or any other special symbols."""
#
#     messages += f'''You are creating a recipe for {cuisine} cuisine.
#                     Ensure {ingredients} are in the recipe. The dietary preference is
#                     {dietary_preference}. The allergies are {allergy}. The meal type is {meal_type}.
#                     The difficulty is {difficulty}.
#                     Remarks are (Ignore this part if irrelevant) {remarks}'''
#
#     print(messages)
#     response = model.generate_content(messages)
#     cleaned = response.text
#     cleaned = cleaned.replace("## ", "")
#     cleaned = cleaned.replace("**", "")
#     cleaned = cleaned.replace("* ", "- ")
#
#     print(cleaned)
#     return jsonify({'content': cleaned})









