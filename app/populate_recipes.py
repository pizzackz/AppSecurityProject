import logging
from flask_sqlalchemy import SQLAlchemy
from app.models import db, User, Admin, Member, MenuItem, Recipe
from app import db
import json
import datetime

recipes = [
    {
        'name': 'Grilled Cheese Sandwich',
        'ingredients': json.dumps(['Bread', 'Cheese', 'Butter']),
        'instructions': '1. Butter the bread. 2. Place cheese between slices. 3. Grill until golden brown.',
        'picture': 'grilledcheese.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 300,
        'prep_time': 10
    },
    {
        'name': 'Caesar Salad',
        'ingredients': json.dumps(['Romaine lettuce', 'Caesar dressing', 'Parmesan cheese', 'Croutons']),
        'instructions': '1. Chop lettuce. 2. Add dressing and mix. 3. Top with cheese and croutons.',
        'picture': 'caesarsalad.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 200,
        'prep_time': 15
    },
    {
        'name': 'Chocolate Cake',
        'ingredients': json.dumps(['Flour', 'Sugar', 'Cocoa powder', 'Baking powder', 'Eggs', 'Milk', 'Butter']),
        'instructions': '1. Preheat oven to 350F. 2. Mix dry ingredients. 3. Add wet ingredients and mix. 4. Bake for 30 minutes.',
        'picture': 'chocolatecake.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 450,
        'prep_time': 60
    },
    # Adding 24 more recipes
    {
        'name': 'Spaghetti Carbonara',
        'ingredients': json.dumps(['Spaghetti', 'Eggs', 'Parmesan cheese', 'Pancetta', 'Black pepper']),
        'instructions': '1. Cook spaghetti. 2. Cook pancetta. 3. Mix eggs and cheese. 4. Combine all and serve.',
        'picture': 'spaghetticarbonara.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 500,
        'prep_time': 20
    },
    {
        'name': 'Chicken Curry',
        'ingredients': json.dumps(['Chicken', 'Curry powder', 'Coconut milk', 'Onions', 'Garlic']),
        'instructions': '1. Cook chicken. 2. Add onions and garlic. 3. Add curry powder and coconut milk. 4. Simmer until done.',
        'picture': 'chickencurry.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 400,
        'prep_time': 45
    },
    {
        'name': 'Beef Tacos',
        'ingredients': json.dumps(['Ground beef', 'Taco seasoning', 'Tortillas', 'Lettuce', 'Tomato', 'Cheese']),
        'instructions': '1. Cook beef with seasoning. 2. Warm tortillas. 3. Assemble tacos with toppings.',
        'picture': 'beeftacos.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 350,
        'prep_time': 25
    },
    {
        'name': 'Margarita Pizza',
        'ingredients': json.dumps(['Pizza dough', 'Tomato sauce', 'Mozzarella', 'Basil', 'Olive oil']),
        'instructions': '1. Roll out dough. 2. Add sauce and toppings. 3. Bake until crust is golden.',
        'picture': 'margaritapizza.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 800,
        'prep_time': 30
    },
    {
        'name': 'Beef Stroganoff',
        'ingredients': json.dumps(['Beef', 'Mushrooms', 'Onions', 'Sour cream', 'Beef broth']),
        'instructions': '1. Cook beef. 2. Add mushrooms and onions. 3. Stir in broth and sour cream. 4. Simmer until thickened.',
        'picture': 'beefstroganoff.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 600,
        'prep_time': 40
    },
    {
        'name': 'Vegetable Stir Fry',
        'ingredients': json.dumps(['Mixed vegetables', 'Soy sauce', 'Garlic', 'Ginger', 'Rice']),
        'instructions': '1. Cook vegetables with garlic and ginger. 2. Add soy sauce. 3. Serve over rice.',
        'picture': 'vegetablestirfry.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 250,
        'prep_time': 15
    },
    {
        'name': 'French Onion Soup',
        'ingredients': json.dumps(['Onions', 'Beef broth', 'Butter', 'Bread', 'Gruyere cheese']),
        'instructions': '1. Cook onions in butter. 2. Add broth and simmer. 3. Top with bread and cheese, then broil.',
        'picture': 'frenchonionsoup.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 350,
        'prep_time': 60
    },
    {
        'name': 'Lemon Garlic Shrimp',
        'ingredients': json.dumps(['Shrimp', 'Lemon', 'Garlic', 'Butter', 'Parsley']),
        'instructions': '1. Cook shrimp with garlic and butter. 2. Add lemon juice. 3. Garnish with parsley.',
        'picture': 'lemongarlicshrimp.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 300,
        'prep_time': 20
    },
    {
        'name': 'BBQ Ribs',
        'ingredients': json.dumps(['Pork ribs', 'BBQ sauce', 'Spices']),
        'instructions': '1. Season ribs. 2. Cook ribs in oven. 3. Brush with BBQ sauce and serve.',
        'picture': 'bbqribs.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 700,
        'prep_time': 120
    },
    {
        'name': 'Greek Salad',
        'ingredients': json.dumps(['Cucumber', 'Tomato', 'Feta cheese', 'Olives', 'Red onion', 'Olive oil']),
        'instructions': '1. Chop vegetables. 2. Mix with feta and olives. 3. Drizzle with olive oil.',
        'picture': 'greeksalad.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 200,
        'prep_time': 10
    },
    {
        'name': 'Tom Yum Soup',
        'ingredients': json.dumps(['Shrimp', 'Lemongrass', 'Kaffir lime leaves', 'Mushrooms', 'Chili']),
        'instructions': '1. Boil broth with lemongrass and lime leaves. 2. Add mushrooms and shrimp. 3. Serve hot.',
        'picture': 'tomyumsoup.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 250,
        'prep_time': 30
    },
    {
        'name': 'Banana Pancakes',
        'ingredients': json.dumps(['Banana', 'Eggs', 'Flour', 'Milk', 'Baking powder']),
        'instructions': '1. Mash bananas. 2. Mix with eggs, flour, milk, and baking powder. 3. Cook on griddle.',
        'picture': 'bananapancakes.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 350,
        'prep_time': 15
    },
    {
        'name': 'Chicken Alfredo',
        'ingredients': json.dumps(['Chicken', 'Fettuccine', 'Cream', 'Parmesan cheese', 'Butter']),
        'instructions': '1. Cook fettuccine. 2. Cook chicken. 3. Make sauce with cream, cheese, and butter. 4. Combine and serve.',
        'picture': 'chickenalfredo.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 700,
        'prep_time': 30
    },
    {
        'name': 'Fish Tacos',
        'ingredients': json.dumps(['Fish fillets', 'Tortillas', 'Cabbage', 'Lime', 'Sour cream']),
        'instructions': '1. Cook fish. 2. Warm tortillas. 3. Assemble tacos with fish, cabbage, lime, and sour cream.',
        'picture': 'fishtacos.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 300,
        'prep_time': 20
    },
    {
        'name': 'Baked Ziti',
        'ingredients': json.dumps(['Ziti', 'Marinara sauce', 'Ricotta cheese', 'Mozzarella', 'Parmesan']),
        'instructions': '1. Cook ziti. 2. Layer with sauce and cheeses. 3. Bake until bubbly.',
        'picture': 'bakedziti.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 600,
        'prep_time': 45
    },
    {
        'name': 'Avocado Toast',
        'ingredients': json.dumps(['Avocado', 'Bread', 'Salt', 'Pepper', 'Lemon']),
        'instructions': '1. Toast bread. 2. Mash avocado with salt, pepper, and lemon. 3. Spread on toast.',
        'picture': 'avocadotoast.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 200,
        'prep_time': 10
    },
    {
        'name': 'Stuffed Peppers',
        'ingredients': json.dumps(['Bell peppers', 'Ground beef', 'Rice', 'Tomato sauce', 'Cheese']),
        'instructions': '1. Cook beef and rice. 2. Stuff peppers with beef, rice, and sauce. 3. Bake with cheese on top.',
        'picture': 'stuffedpeppers.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 400,
        'prep_time': 60
    },
    {
        'name': 'Eggplant Parmesan',
        'ingredients': json.dumps(['Eggplant', 'Marinara sauce', 'Mozzarella', 'Parmesan', 'Breadcrumbs']),
        'instructions': '1. Bread and fry eggplant. 2. Layer with sauce and cheese. 3. Bake until golden.',
        'picture': 'eggplantparmesan.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 500,
        'prep_time': 45
    },
    {
        'name': 'Minestrone Soup',
        'ingredients': json.dumps(['Mixed vegetables', 'Pasta', 'Beans', 'Tomato broth', 'Herbs']),
        'instructions': '1. Cook vegetables in broth. 2. Add pasta and beans. 3. Simmer until pasta is tender.',
        'picture': 'minestronesoup.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 300,
        'prep_time': 40
    },
    {
        'name': 'Shrimp Scampi',
        'ingredients': json.dumps(['Shrimp', 'Garlic', 'Butter', 'Lemon', 'Parsley']),
        'instructions': '1. Cook shrimp with garlic and butter. 2. Add lemon juice and parsley. 3. Serve with pasta.',
        'picture': 'shrimpscampi.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 400,
        'prep_time': 20
    },
    {
        'name': 'Chicken Noodle Soup',
        'ingredients': json.dumps(['Chicken', 'Egg noodles', 'Carrots', 'Celery', 'Chicken broth']),
        'instructions': '1. Cook chicken in broth. 2. Add vegetables and noodles. 3. Simmer until noodles are tender.',
        'picture': 'chickennoodlesoup.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 250,
        'prep_time': 30
    },
    {
        'name': 'Pad Thai',
        'ingredients': json.dumps(['Rice noodles', 'Shrimp', 'Eggs', 'Peanuts', 'Bean sprouts', 'Pad Thai sauce']),
        'instructions': '1. Cook noodles. 2. Stir-fry shrimp and eggs. 3. Add noodles, sauce, and sprouts. 4. Garnish with peanuts.',
        'picture': 'padthai.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 450,
        'prep_time': 25
    },
    {
        'name': 'Tuna Salad',
        'ingredients': json.dumps(['Tuna', 'Mayonnaise', 'Celery', 'Onion', 'Lemon']),
        'instructions': '1. Mix tuna with mayonnaise, celery, and onion. 2. Add lemon juice. 3. Serve chilled.',
        'picture': 'tunasalad.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Standard',
        'calories': 200,
        'prep_time': 10
    },
    {
        'name': 'Baked Salmon',
        'ingredients': json.dumps(['Salmon', 'Lemon', 'Dill', 'Olive oil']),
        'instructions': '1. Preheat oven. 2. Place salmon on baking sheet. 3. Drizzle with olive oil, lemon, and dill. 4. Bake until cooked through.',
        'picture': 'bakedsalmon.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'admin',
        'type': 'Premium',
        'calories': 350,
        'prep_time': 25
    }
]

def populate_recipes():
    for i in recipes:
        name = i['name']
        ingredients = i['ingredients']
        instructions = i['instructions']
        picture = i['picture']
        date_created = i['date_created']
        user_created = i['user_created']
        recipe_type = i['type']
        calories = i['calories']
        prep_time = i['prep_time']
        new_recipe = Recipe(name=name, ingredients=ingredients, instructions=instructions, picture=picture, user_created=user_created, type=recipe_type, calories=calories,
                            prep_time=prep_time)
        db.session.add(new_recipe)
        db.session.commit()
        print(f"Recipe {name} added to database")



