from flask import Flask, current_app, Blueprint, render_template, request, redirect, session, flash, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import shelve
import os
# from ..forms import CreateRecipeForm
import pymysql
import cryptography
from datetime import datetime
import sqlite3

app = Flask(__name__)



# mydb = pymysql.connect(
#     host='localhost',
#     user='root',
#     password='password123'
# )
# print(mydb)
#
# my_cursor = mydb.cursor()
# my_cursor.execute("SHOW DATABASES")
#
# for db in my_cursor:
#     print(db) # Prints all the databases in the server




# Recipe Pages
# @admin_bp.route('/<string:id>/admin/recipe_database', methods=['GET', 'POST'])
# @admin_login_required
# def recipe_database(id):
#     db = shelve.open('recipes.db', 'c')
#
#     try:
#         recipe_dict = db['recipes']
#     except:
#         print('Error in retrieving recipes')
#         recipe_dict = {}
#
#     recipes = []
#     for key in recipe_dict:
#         recipe = recipe_dict.get(key)
#         recipes.append(recipe)
#         # For debugging
#         print(recipe.get_name(), recipe.get_id())
#
#     print(recipes)
#     if request.method == 'POST':
#         ingredients = request.form.get('ingredient')
#         ingredients = ingredients.split(',')
#         print(ingredients)
#         recipe2 = []
#         for i in range(0, len(ingredients)):
#             for s in range(0, len(recipes)):
#                 name = (recipes[s]).get_name()
#                 name = name.lower()
#                 if ingredients[i] in (recipes[s]).get_ingredients() or ingredients[i] in name:
#                     if recipes[s] not in recipe2:
#                         recipe2.append(recipes[s])
#
#         db.close()
#         return render_template('admin/recipe_database.html', recipes=recipe2, id=id)
#
#     db.close()
#     return render_template('admin/recipe_database.html', recipes=recipes, id=id)
#
#
# @admin_bp.route('/<string:id>/admin/create_recipe', methods=['GET', 'POST'])
# @admin_login_required
# def create_recipe(id):
#     create_recipe_form = CreateRecipeForm(request.form)
#     if request.method == 'POST':
#         db = shelve.open('recipes.db', 'c')
#         recipe_dict = db.setdefault('recipes', {})  # Initialize if 'recipes' doesn't exist
#         recipe_dict = db['recipes']
#
#         name = create_recipe_form.name.data
#         picture = request.files['picture']
#         print(picture.filename)
#
#         picture_filename = picture.filename
#         picture_filename = picture_filename.split('.')
#         print(picture_filename[1])
#
#         if picture_filename[1] != 'jpg' and picture_filename[1] != 'png':
#             return render_template('admin/create_recipe.html', alert_error='Images are only allowed',
#                                    form=create_recipe_form, id=id)
#
#         picture_filename = name + '.' + picture_filename[1]
#         picture.save(os.path.join('static/images_recipe', picture_filename))
#
#         name = create_recipe_form.name.data
#
#         ingredients = create_recipe_form.ingredients.data
#         ingredients = ingredients.split(',')
#         print(ingredients)
#         if ingredients == ['']:
#             return render_template('admin/create_recipe.html', alert_error='Please add ingredients.',
#                                    form=create_recipe_form, id=id)
#
#         new_recipe = Recipe(create_recipe_form.name.data, ingredients, create_recipe_form.instructions.data,
#                             picture_filename)
#
#         print(new_recipe.get_instructions())
#
#         for key in recipe_dict:
#             recipe = recipe_dict.get(key)
#             if name == recipe.get_name():
#                 return render_template('admin/create_recipe.html', alert_error='Recipe exists in Database.',
#                                        form=create_recipe_form, id=id)
#
#         recipe_dict[new_recipe.get_id()] = new_recipe
#         db['recipes'] = recipe_dict
#
#         db.close()
#
#         flash(f'{name} has been created', 'success')
#
#         return redirect(url_for('admin.recipe_database', id=id))
#
#     return render_template('admin/create_recipe.html', form=create_recipe_form, id=id)
#
#
# @admin_bp.route('/<string:id>/admin/view_recipe/<recipe_id>', methods=['GET', 'POST'])
# @admin_login_required
# def view_recipe(recipe_id, id):
#     print(recipe_id)
#     db = shelve.open('recipes.db', 'c')
#     recipe_dict = db['recipes']
#     recipe = recipe_dict.get(recipe_id)
#     print(recipe.get_instructions())
#     db.close()
#     return render_template('admin/view_recipe.html', recipe=recipe, id=id)
#
#
# @admin_bp.route('/<string:id>/admin/edit_recipe/<recipe_id>', methods=['GET', 'POST'])
# @admin_login_required
# def edit_recipe(recipe_id, id):
#     db = shelve.open('recipes.db', 'c')
#     recipe_dict = db['recipes']
#     recipe = recipe_dict.get(recipe_id)
#
#     update_recipe_form = CreateRecipeForm(request.form)
#
#     if request.method == 'POST':
#         name = update_recipe_form.name.data
#         ingredients = update_recipe_form.ingredients.data
#         ingredients = ingredients.split(',')
#         instructions = update_recipe_form.instructions.data
#         picture = request.files['picture']
#
#         if picture.filename != '':
#             old_picture = recipe.get_picture()
#             if old_picture:
#                 os.remove(os.path.join('static/images_recipe', old_picture))
#             recipe.set_picture(picture.filename)
#             picture.save(os.path.join('static/images_recipe', picture.filename))
#
#         if name != '':
#             recipe.set_name(name)
#         if ingredients != []:
#             recipe.set_ingredients(ingredients)
#         if instructions != '':
#             recipe.set_instructions(instructions)
#
#         db['recipes'] = recipe_dict
#         db.close()
#
#         flash(f'{recipe.get_name()} has been updated', 'info')
#
#         return redirect(url_for('admin.recipe_database', id=id))
#
#     update_recipe_form.name.data = recipe.get_name()
#     print(recipe.get_name())
#     update_recipe_form.instructions.data = recipe.get_instructions()
#
#     ingredients = recipe.get_ingredients()
#
#     return render_template('admin/update_recipe.html', form=update_recipe_form, ingredients=ingredients, id=id)
#
#
# @admin_bp.route('/<string:id>/admin/delete_recipe/<recipe_id>')
# @admin_login_required
# def delete_recipe(recipe_id, id):
#     db = shelve.open('recipes.db', 'c')
#     recipe_dict = db['recipes']
#
#     recipe = recipe_dict.get(recipe_id)
#     old_picture = recipe.get_picture()
#     if old_picture:
#         os.remove(os.path.join('static/images_recipe', old_picture))
#
#     name = recipe.get_name()
#
#     recipe_dict.pop(recipe_id)
#     db['recipes'] = recipe_dict
#     db.close()
#
#     flash(f'{name} has been deleted', 'info')
#
#     return redirect(url_for('admin.recipe_database', id=id))
