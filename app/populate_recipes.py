import logging
from flask_sqlalchemy import SQLAlchemy
from app.models import db, User, Admin, Member, MenuItem, Recipe
from app import db
import json
import datetime

recipes = [
    {
        'name': 'Classic Pancakes',
        'ingredients': 'Flour,Milk,Eggs,Sugar,Butter,Baking Powder,Vanilla Extract,Pinch of Salt',
        'instructions': '1. Mix dry ingredients. 2. Add wet ingredients and mix until smooth. 3. Cook on a hot griddle until golden brown.',
        'picture': 'pancakes.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'chef_jane',
        'user_created_id': 12345,
        'type': 'Standard',
        'calories': 220,
        'prep_time': 15
    },
    {
        'name': 'Caesar Salad',
        'ingredients': 'Romaine Lettuce,Caesar Dressing,Parmesan Cheese,Croutons,Lemon Juice,Black Pepper',
        'instructions': '1. Chop lettuce. 2. Toss with dressing and lemon juice. 3. Top with Parmesan and croutons.',
        'picture': 'caesar_salad.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'salad_lover',
        'user_created_id': 67890,
        'type': 'Premium',
        'calories': 180,
        'prep_time': 10
    },
    {
        'name': 'Spaghetti Bolognese',
        'ingredients': 'Spaghetti,Ground Beef,Tomato Sauce,Onion,Garlic,Olive Oil,Carrot,Red Wine,Oregano,Basil,Salt,Pepper',
        'instructions': '1. Cook spaghetti according to package instructions. 2. Sauté onions and garlic in olive oil. 3. Add ground beef and cook until browned. 4. Stir in tomato sauce, carrot, and red wine. 5. Simmer for 20 minutes. 6. Serve sauce over spaghetti.',
        'picture': 'spaghetti_bolognese.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'pasta_master',
        'user_created_id': 54321,
        'type': 'Private',
        'calories': 450,
        'prep_time': 30
    },
    {
        'name': 'Chocolate Chip Cookies',
        'ingredients': 'Butter,Sugar,Brown Sugar,Eggs,Vanilla Extract,Flour,Baking Soda,Salt,Chocolate Chips',
        'instructions': '1. Cream together butter and sugars. 2. Add eggs and vanilla, mix well. 3. Stir in dry ingredients, then fold in chocolate chips. 4. Drop by spoonfuls onto a baking sheet. 5. Bake at 350°F for 10-12 minutes.',
        'picture': 'chocolate_chip_cookies.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'baking_queen',
        'user_created_id': 98765,
        'type': 'Standard',
        'calories': 150,
        'prep_time': 20
    },
    {
        'name': 'Margarita Pizza',
        'ingredients': 'Pizza Dough,Tomato Sauce,Mozzarella Cheese,Basil,Olive Oil,Salt',
        'instructions': '1. Preheat oven to 475°F. 2. Roll out dough on a floured surface. 3. Spread tomato sauce over dough. 4. Top with mozzarella and basil. 5. Drizzle with olive oil and sprinkle with salt. 6. Bake for 10-15 minutes.',
        'picture': 'margarita_pizza.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'pizza_fan',
        'user_created_id': 13579,
        'type': 'Standard',
        'calories': 250,
        'prep_time': 20
    },
    {
        'name': 'Chicken Curry',
        'ingredients': 'Chicken,Basmati Rice,Coconut Milk,Curry Paste,Onion,Garlic,Ginger,Oil,Cilantro',
        'instructions': '1. Cook rice according to package instructions. 2. Sauté onions, garlic, and ginger in oil. 3. Add chicken and cook until browned. 4. Stir in curry paste and coconut milk. 5. Simmer until chicken is cooked through. 6. Serve over rice and garnish with cilantro.',
        'picture': 'chicken_curry.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'spice_master',
        'user_created_id': 24680,
        'type': 'Premium',
        'calories': 400,
        'prep_time': 30
    },
    {
        'name': 'Greek Salad',
        'ingredients': 'Cucumber,Tomato,Red Onion,Feta Cheese,Olives,Olive Oil,Lemon Juice,Oregano,Salt,Pepper',
        'instructions': '1. Chop cucumber, tomato, and red onion. 2. Combine in a bowl with olives and feta. 3. Drizzle with olive oil and lemon juice. 4. Sprinkle with oregano, salt, and pepper. 5. Toss to combine.',
        'picture': 'greek_salad.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'greek_guru',
        'user_created_id': 11223,
        'type': 'Standard',
        'calories': 150,
        'prep_time': 10
    },
    {
        'name': 'Tacos al Pastor',
        'ingredients': 'Pork,Onion,Pineapple,Corn Tortillas,Cilantro,Lime,Chili Powder,Garlic Powder,Oregano,Salt',
        'instructions': '1. Marinate pork in chili powder, garlic powder, oregano, and salt. 2. Cook pork with onions and pineapple until tender. 3. Warm tortillas and fill with pork mixture. 4. Top with cilantro and a squeeze of lime.',
        'picture': 'tacos_al_pastor.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'taco_king',
        'user_created_id': 33445,
        'type': 'Private',
        'calories': 320,
        'prep_time': 25
    },
    {
        'name': 'Banana Smoothie',
        'ingredients': 'Banana,Milk,Honey,Yogurt,Vanilla Extract,Ice',
        'instructions': '1. Combine banana, milk, honey, yogurt, vanilla, and ice in a blender. 2. Blend until smooth. 3. Serve immediately.',
        'picture': 'banana_smoothie.png',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'smoothie_lover',
        'user_created_id': 55667,
        'type': 'Standard',
        'calories': 180,
        'prep_time': 5
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
        user_created_id = i['user_created_id']
        recipe_type = i['type']
        calories = i['calories']
        prep_time = i['prep_time']
        new_recipe = Recipe(name=name, ingredients=ingredients, instructions=instructions, picture=picture, user_created=user_created, user_created_id=user_created_id, type=recipe_type, calories=calories,
                            prep_time=prep_time)
        db.session.add(new_recipe)
        db.session.commit()
        print(f"Recipe {name} added to database")



