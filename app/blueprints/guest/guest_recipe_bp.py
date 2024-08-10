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
    jsonify,
    abort,
    make_response
)
import re
import imghdr
import imageio
from app.models import Recipe, User, RecipeConfig
from app import db
import os
from sqlalchemy import or_, and_, case
from flask_login import current_user, login_required
from app.forms.forms import RecipeSearch

guest_recipe_bp = Blueprint("guest_recipe_bp", __name__)

@guest_recipe_bp.route("/guest_recipe_database", methods=["GET", "POST"])
def recipe_database():
    try:
        user_type = current_user.type
        if user_type == 'admin':
            return redirect(url_for('admin_recipe_bp.recipe_database'))
        elif user_type == 'member':
            return redirect(url_for('member_recipe_bp.recipe_database'))
    except AttributeError:
        print('Guest confirmed')
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
            return redirect(url_for('guest_recipe_bp.recipe_database'))
        else:
            print('Success')
            ingredients = form.ingredients.data
            try:
                ingredients = ingredients.split(',')
            except:
                flash('Error processing ingredients', 'error')
                return redirect(url_for('guest_recipe_bp.recipe_database'))

            # Clean data
            if ingredients == []:  # If empty, redirect
                flash('Ingredients are empty!', 'error')
                return redirect(url_for('guest_recipe_bp.recipe_database'))
                # return redirect

            # If not pass regex, redirect
            regex = r'^[a-zA-Z ]+$'  # Regex pattern allowing only letters and spaces
            for i in range(len(ingredients)):
                ingredients[i] = (ingredients[i]).strip()
                if ingredients[i] == '':
                    flash('Ingredients are empty!', 'error')
                    return redirect(url_for('guest_recipe_bp.recipe_database'))
                if not re.fullmatch(regex, ingredients[i]):
                    flash('Only letters and spaces allowed', 'error')
                    return redirect(url_for('guest_recipe_bp.recipe_database'))
                if len(ingredients[i]) > 20:
                    flash('Ingredient cannot be more than 20 characters', 'error')
                    return redirect(url_for('guest_recipe_bp.recipe_database'))
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
                            Recipe.type == 'Premium'
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

            return render_template("guest/recipe/recipe_database.html", form=form, recipes=search_results,
                                   total_pages=total_pages, page=page)

    # Get pages
    total_pages = (Recipe.query.count() // per_page) + 1
    print(f'Total pages: {total_pages}')
    print(f'There are {Recipe.query.count()} recipe')

    items_on_page = Recipe.query.filter(
        or_(
            Recipe.type == 'Standard',
            Recipe.type == 'Premium'
        )
    ).order_by(
        case(
            (Recipe.type == 'Private', 0),  # Ensure 'Private' recipes appear first
            else_=1
        )
    ).slice(start, end).all()

    return render_template("guest/recipe/recipe_database.html", form=form, recipes=items_on_page,
                           total_pages=total_pages, page=page)


@guest_recipe_bp.route('/guest_view_recipe/<recipe_id>', methods=['GET', 'POST'])
def view_recipe(recipe_id):
    recipe = Recipe.query.filter_by(id=recipe_id).first()
    try:
        user_type = current_user.type
        if user_type == 'admin':
            return redirect(url_for('admin_recipe_bp.view_recipe', recipe_id=recipe_id))
        elif user_type == 'member':
            return redirect(url_for('member_recipe_bp.view_recipe', recipe_id=recipe_id))
    except AttributeError:
        print('Guest confirmed')
    if recipe == None:
        abort(404)
    if recipe.type == 'Private' or recipe.type == 'Premium':
        flash('Action cannot be done', 'error')
        return redirect(url_for('guest_recipe_bp.recipe_database'))
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
    return render_template('guest/recipe/recipe_view2.html', recipe=recipe_data)