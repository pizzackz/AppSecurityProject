from flask import (
    Flask,
    current_app,
    Blueprint,
    render_template,
    request,
    redirect,
    session,
    flash,
    url_for,
)
import re
import imghdr
import imageio
import requests
from werkzeug.utils import secure_filename
from app.models import Recipe
import os
from sqlalchemy import or_
import json


from PIL import Image
from html import unescape
# import flask_sqlalchemy
# from app.models import Recipe
# from werkzeug.utils import secure_filename
# from werkzeug.security import generate_password_hash, check_password_hash

# from sqlalchemy import text
from datetime import datetime

# import random
# import sys
import html

from app.forms import CreateRecipeForm, RecipeSearch
from app import db
from bs4 import BeautifulSoup

admin_recipe_bp = Blueprint("admin_recipe_bp", __name__)


def clean_input(html):
    cleaned = html.unescape(html)
    return cleaned

def is_image(filename):
    # Check if the file is an image
    image_type = imghdr.what(filename)
    if image_type is not None:
        return True, image_type
    else:
        return False, None

def is_square_image(filename):
    image_type = imghdr.what(filename)
    with imageio.imread(filename) as img:
        height, width, _ = img.shape
        if width == height:
            return True, image_type
        else:
            return False, None

# Recipe Pages
@admin_recipe_bp.route("/admin/recipe_database", methods=["GET", "POST"])
def recipe_database():
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


            total_pages = (len(search_results) // per_page) + 1
            search_results = search_results[start:end]

            return render_template("admin/recipe/recipe_database.html", form=form, recipes=search_results, total_pages=total_pages, page=page)

    # Get pages
    total_pages = (Recipe.query.count() // per_page) + 1
    print(f'Total pages: {total_pages}')
    print(f'There are {Recipe.query.count()} recipes')

    items_on_page = Recipe.query.slice(start, end)

    return render_template("admin/recipe/recipe_database.html", form=form, recipes=items_on_page, total_pages=total_pages, page=page)

@admin_recipe_bp.route('/admin/create_recipe', methods=['GET', 'POST'])
def create_recipe():
    form = CreateRecipeForm()

    if request.method == "POST":
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

            # PROCESS INSTRUCTIONS
            instructions = instructions.strip()
            if instructions == '':
                flash('Instructions are empty!', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            if len(instructions) > 1000:
                flash('Instructions cannot be more than 1000 characters', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            html.unescape(instructions)
            # Parse HTML
            soup = BeautifulSoup(instructions, 'html.parser')

            # Remove all script tags
            for script in soup(["script", "style"]):
                script.decompose()
            # Remove all iFrame and input tags
            for iframe in soup(["iframe", "input", "link", "submit", "link", "meta"]):
                iframe.decompose()

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
            if recipe_type != 'Standard' and recipe_type != 'Premium':
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
            # if not is_square_image(picture):
            #     flash('Image size must be 1:1', 'error')
            #     return redirect(url_for('admin_recipe_bp.create_recipe'))

            def scan_image_for_malware(api_key, filename):
                url = 'https://www.virustotal.com/vtapi/v2/file/scan'
                params = {'apikey': api_key}
                with open(filename, 'rb') as file:
                    files = {'file': file}
                    response = requests.post(url, files=files, params=params)
                    result = response.json()
                return result

            def is_image_safe(result):
                if 'response_code' in result and result['response_code'] == 1:
                    if 'positives' in result and result['positives'] == 0:
                        return True
                return False

            api_key = 'your_virustotal_api_key'
            filename = picture.filename

            # result = scan_image_for_malware(api_key, filename)

            # if not is_image_safe(result):
            #     print("The image is not safe. Proceed with using it.")
            #     flash('Please reupload the image', 'error')
            #     return redirect(url_for('admin_recipe_bp.create_recipe'))

            # Save the image file
            picture_filename = picture.filename
            picture_filename = picture_filename.split('.')
            picture_filename = name + '.' + picture_filename[1]

            picture.save(os.path.join('app/static/images_recipe', picture_filename))

            # Store in database
            new_recipe = Recipe(name=name, ingredients=ingredient_cleaned, instructions=instructions, picture=picture_filename, type=recipe_type, calories=calories, prep_time=prep_time, user_created='JohnDoeTesting')
            try:
                db.session.add(new_recipe)
                db.session.commit()
            except:
                print('Error in creating recipe:')
                flash('An error occurred while creating the recipe. Please try again.', 'danger')
            print('Success')
            return redirect(url_for('admin_recipe_bp.recipe_database'))
    return render_template('admin/recipe/recipe_create.html', form=form)


@admin_recipe_bp.route('/admin/view_recipe/<recipe_id>', methods=['GET', 'POST'])
def view_recipe(recipe_id):
    recipe = Recipe.query.filter_by(id=recipe_id).first()
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
def delete_recipe(recipe_id):
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    flash(f'{recipe.name} was deleted', 'info')
    db.session.delete(recipe)
    db.session.commit()
    return redirect(url_for('admin_recipe_bp.recipe_database'))

@admin_recipe_bp.route('/admin/update_recipe/<recipe_id>', methods=['GET', 'POST'])
def update_recipe(recipe_id):
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    form = CreateRecipeForm()
    if request.method == 'POST':
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

        if instructions != '':
            if len(instructions) > 1000:
                flash('Instructions cannot be more than 1000 characters', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
            html.unescape(instructions)
            # Parse HTML
            soup = BeautifulSoup(instructions, 'html.parser')

            # Remove all script tags
            for script in soup(["script", "style"]):
                script.decompose()
            # Remove all iFrame and input tags
            for iframe in soup(["iframe", "input", "link", "submit", "link", "meta"]):
                iframe.decompose()

        # PROCESS CALORIES
        if calories != '':
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
        if prep_time != '':
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
        if recipe_type != 'Standard' and recipe_type != 'Premium':
            flash('Invalid recipe type', 'error')
            return redirect(url_for('admin_recipe_bp.create_recipe'))

        # PROCESS INGREDIENTS
        try:
            ingredients = ingredients.split(',')
        except:
            flash('Error processing ingredients', 'error')
            return redirect(url_for('admin_recipe_bp.create_recipe'))

        # Clean data
        if ingredients != []:
            # If not pass regex, redirect
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            print(ingredients)
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

        # PROCESS IMAGE
        if picture.filename != '':
            if not is_image(picture):
                flash('Invalid image format', 'error')
                return redirect(url_for('admin_recipe_bp.create_recipe'))
                # Save the image file
            picture_filename = picture.filename
            picture_filename = picture_filename.split('.')
            picture_filename = name + '.' + picture_filename[1]
            picture.save(os.path.join('app/static/images_recipe', picture_filename))

        if name != '':
            recipe.name = name
        if ingredients != []:
            recipe.ingredients = ingredient_cleaned
        if instructions != '':
            recipe.instructions = instructions
        if picture.filename != '':
            recipe.picture = picture_filename
        if calories != '':
            recipe.calories = calories
        if prep_time != '':
            recipe.prep_time = prep_time
        recipe.type = recipe_type

        db.session.commit()
        flash(f'{recipe.name} updated', 'info')
        return redirect(url_for('admin_recipe_bp.recipe_database'))

    form.name.data = recipe.name

    form.instructions.data = recipe.instructions
    form.calories.data = recipe.calories
    form.prep_time.data = recipe.prep_time
    form.recipe_type.data = recipe.type
    ingredients = (recipe.ingredients).split(',')


    return render_template('admin/recipe/recipe_update.html', form=form, ingredients=ingredients)



@admin_recipe_bp.route('/populate_recipes')
def populate_recipes():
    from app.populate_recipes import populate_recipes
    populate_recipes()
    return 'Populated recipes'










# @admin_recipe_bp.route('/admin/edit_recipe/<recipe_id>', methods=['GET', 'POST'])
# def edit_recipe(recipe_id, id):
#     try:
#         with db.cursor() as cursor:
#             # Retrieve the recipe from the database using its ID
#             cursor.execute("SELECT * FROM recipes WHERE id=%s", (recipe_id,))
#             recipe = cursor.fetchone()
#             if not recipe:
#                 return "Recipe not found"
#
#             if request.method == 'POST':
#                 name = request.form.get('name')
#                 ingredients = request.form.get('ingredients').split(',')
#                 instructions = request.form.get('instructions')
#                 picture = request.files.get('picture')
#
#                 # Update recipe data in the database
#                 if picture.filename:
#                     old_picture = recipe['picture']
#                     if old_picture:
#                         os.remove(os.path.join('static/images_recipe', old_picture))
#                     picture_filename = secure_filename(picture.filename)
#                     picture.save(os.path.join('static/images_recipe', picture_filename))
#                     cursor.execute("UPDATE recipes SET picture=%s WHERE id=%s", (picture_filename, recipe_id))
#
#                 if name:
#                     cursor.execute("UPDATE recipes SET name=%s WHERE id=%s", (name, recipe_id))
#                 if ingredients:
#                     cursor.execute("UPDATE recipes SET ingredients=%s WHERE id=%s", (','.join(ingredients), recipe_id))
#                 if instructions:
#                     cursor.execute("UPDATE recipes SET instructions=%s WHERE id=%s", (instructions, recipe_id))
#
#                 db.commit()
#                 flash(f'{recipe["name"]} has been updated', 'info')
#                 return redirect(url_for('admin.recipe_database', id=id))
#
        # return render_template('admin/recipe_update.html')
#     except Exception as e:
#         print('Error in editing recipe:', str(e))
#         flash('An error occurred while editing the recipe', 'danger')
#         return redirect(url_for('admin.recipe_database', id=id))
#
#
# @admin_recipe_bp.route('/admin/delete_recipe/<recipe_id>')
# def delete_recipe(recipe_id, id):
#     try:
#         with db.cursor() as cursor:
#             # Retrieve the recipe from the database using its ID
#             cursor.execute("SELECT * FROM recipes WHERE id=%s", (recipe_id,))
#             recipe = cursor.fetchone()
#             if not recipe:
#                 return "Recipe not found"
#
#             # Delete the recipe from the database
#             cursor.execute("DELETE FROM recipes WHERE id=%s", (recipe_id,))
#             db.commit()
#
#             # Delete the recipe's picture file
#             old_picture = recipe['picture']
#             if old_picture:
#                 os.remove(os.path.join('static/images_recipe', old_picture))
#
#             flash(f'{recipe["name"]} has been deleted', 'info')
#             return redirect(url_for('admin.recipe_database', id=id))
#     except Exception as e:
#         print('Error in deleting recipe:', str(e))
#         flash('An error occurred while deleting the recipe', 'danger')
#         return redirect(url_for('admin.recipe_database', id=id))
