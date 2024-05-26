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
import flask_sqlalchemy
from app.models import Recipe
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
from sqlalchemy import text
from datetime import datetime
import re
import random
import sys
import html

from app.forms import CreateRecipeForm

from app import db

admin_recipe_bp = Blueprint("admin_recipe_bp", __name__)


def clean_input(html):
    cleaned = html.unescape(html)
    return cleaned


# Recipe Pages
@admin_recipe_bp.route("/admin/recipe_database", methods=["GET", "POST"])
def recipe_database():
    print(db)

    """Searching using wildcard * for recipes"""
    # try:
    #     with db.cursor() as cursor:
    #         # Retrieve recipes from the database
    #         cursor.execute("SELECT * FROM recipes")
    #         recipes = cursor.fetchall()
    # except Exception as e:
    #     print('Error in retrieving recipes:', str(e))
    #     recipes = []
    #
    # if request.method == 'POST':
    #     # Getting input from forms
    #     ingredients = request.form.get('ingredient')
    #     print(ingredients)
    #
    #     try:
    #         ingredients = ingredients.split(',')
    #     except:
    #         flash('Error processing ingredients', 'error')
    #         return redirect(url_for('admin_recipe_bp.recipe_database'))
    #
    #     if ingredients == []: # If empty, redirect
    #         flash('Ingredients are empty!', 'error')
    #         return redirect(url_for('admin_recipe_bp.recipe_database'))
    #         # return redirect
    #
    #     # If not pass regex, redirect
    #     regex = r'^[a-zA-Z ]+$'  # Regex pattern for uppercase letter followed by digits
    #     for ingredient in ingredients:
    #         if not re.fullmatch(regex, ingredient):
    #             flash('Only letters and spaces allowed', 'error')
    #             return redirect(url_for('admin_recipe_bp.recipe_database'))
    #         if len(ingredient) > 20:
    #             flash('Ingredient cannot be more than 20 characters', 'error')
    #             return redirect(url_for('admin_recipe_bp.recipe_database'))
    #
    #     # Clean input, remove spaces at front and end
    #     for i in range(len(ingredients)):
    #         ingredients[i] = (ingredients[i]).strip()
    #         ingredients[i] = (ingredients[i]).lower()
    #
    #     try:
    #         # Searching for recipes using ingredients
    #         with db.cursor() as cursor:
    #             recipe2 = []
    #             for ingredient in ingredients:
    #                 # Search for recipes containing the given ingredients
    #                 cursor.execute("SELECT * FROM recipes WHERE ingredients LIKE %s", ("%" + ingredient + "%",))
    #                 recipes_with_ingredient = cursor.fetchall()
    #                 recipe2.extend(recipes_with_ingredient)
    #
    #         return render_template('admin/recipe_database.html', recipes=recipe2)
    #
    #     except Exception as e:
    #         print('Error in searching recipes:', str(e))
    #         return render_template('admin/recipe_database.html', recipes=[])

    return render_template("admin/recipe/recipe_database.html")

@admin_recipe_bp.route('/admin/create_recipe', methods=['GET', 'POST'])
def create_recipe():
    form = CreateRecipeForm()
    if form.validate():
        name = clean_input(form.name.data)
        ingredients = clean_input(form.ingredients.data)
        instructions = clean_input(form.instructions.data)
        picture = form.picture.data
        calories = clean_input(form.calories.data)
        prep_time = clean_input(form.prep_time.data)
        recipe_type = clean_input(form.type.data)




    #     name = create_recipe_form['name']
    #     picture = request.files['picture']
    #     picture_filename = picture.filename
    #
    #     if not picture_filename.endswith(('jpg', 'png')):
    #         return render_template('admin/recipe_create.html', alert_error='Images are only allowed', id=id)
    #
    #     # Save the image file
    #     picture_filename = secure_filename(picture_filename)
    #     picture.save(os.path.join('static/images_recipe', picture_filename))
    #
    #     ingredients = create_recipe_form['ingredients'].split(',')
    #     if not ingredients:
    #         return render_template('admin/recipe_create.html', alert_error='Please add ingredients.', id=id)
    #
    #     instructions = create_recipe_form['instructions']
    #
    #     try:
    #         with db.cursor() as cursor:
    #             # Insert the new recipe into the database
    #             cursor.execute("INSERT INTO recipes (name, ingredients, instructions, picture) VALUES (%s, %s, %s, %s)",
    #                            (name, ','.join(ingredients), instructions, picture_filename))
    #             db.commit()
    #             flash(f'{name} has been created', 'success')
    #             return redirect(url_for('admin.recipe_database', id=id))
    #     except Exception as e:
    #         print('Error in creating recipe:', str(e))
    #         flash('An error occurred while creating the recipe. Please try again.', 'danger')

    return render_template('admin/recipe/recipe_create.html', form=form)


#
# @admin_recipe_bp.route('/admin/view_recipe/<recipe_id>', methods=['GET', 'POST'])
# def view_recipe(recipe_id, id):
#     try:
#         with db.cursor() as cursor:
#             # Retrieve the recipe from the database using its ID
#             cursor.execute("SELECT * FROM recipes WHERE id=%s", (recipe_id,))
#             recipe = cursor.fetchone()
#             if not recipe:
#                 return "Recipe not found"
#             return render_template('admin/recipe_view.html', recipe=recipe, id=id)
#     except Exception as e:
#         print('Error in viewing recipe:', str(e))
#         return "An error occurred while viewing the recipe"
#
#
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
#             return render_template('admin/recipe_update.html', recipe=recipe, id=id)
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
