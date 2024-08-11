from app.models import db, User, Admin, Member, MenuItem, Recipe
from app import db
import datetime
import hashlib
from app.utils import copy_directory

recipes = [
    {
        'name': 'Chicken Soup',
        'ingredients': 'Chicken,Broth,Carrots,Onions,Celery,Garlic,Herbs,Salt,Pepper',
        'instructions': '<p>1. Sauté onions, garlic, carrots, and celery in a pot.</p><p>2. Add chicken and broth, and bring to a boil.</p><p>3. Reduce heat and simmer until chicken is cooked through.</p><p>4. Shred chicken and return to the pot.</p><p>5. Season with herbs, salt, and pepper.</p><p>6. Serve hot.</p>',
        'picture': 'bfd9a66641a2c90a51fbe0301dfe9ee2df6fbc90ea7f164bdba7cf4cf964f161.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'soup_lover',
        'user_created_id': 10001,
        'type': 'Standard',
        'calories': 200,
        'prep_time': 30
    },
    {
        'name': 'Chicken Tacos',
        'ingredients': 'Chicken,Taco Shells,Lettuce,Tomato,Cheese,Sour Cream,Taco Sauce',
        'instructions': '<p>1. Cook chicken with taco seasoning.</p><p>2. Shred chicken and fill taco shells with it.</p><p>3. Top with lettuce, tomato, cheese, sour cream, and taco sauce.</p><p>4. Serve immediately.</p>',
        'picture': f'e6b1ab6a2580d8c390a6018097bac0ac705d6d6605e7911ae9a2129b61220297.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'taco_master',
        'user_created_id': 10002,
        'type': 'Standard',
        'calories': 350,
        'prep_time': 20
    },
    {
        'name': 'Fried Rice',
        'ingredients': 'Rice,Chicken,Carrots,Peas,Onions,Garlic,Egg,Soy Sauce,Oil',
        'instructions': '<p>1. Cook rice and set aside.</p><p>2. Sauté onions, garlic, carrots, and peas in oil.</p><p>3. Add chicken and cook until done.</p><p>4. Push ingredients to the side of the pan and scramble eggs in the space.</p><p>5. Add rice and soy sauce, mix everything together and cook for a few more minutes.</p><p>6. Serve hot.</p>',
        'picture': f'495fe3f7d802654e3c33efae944c25a7f6353c759f9bcb198a944adfe58421a3.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'rice_chef',
        'user_created_id': 10003,
        'type': 'Standard',
        'calories': 300,
        'prep_time': 25
    },
    {
        'name': 'Ham and Cheese Casserole',
        'ingredients': 'Ham,Cheese,Pasta,Milk,Eggs,Butter,Flour,Mustard',
        'instructions': '<p>1. Cook pasta according to package instructions.</p><p>2. In a saucepan, make a cheese sauce with butter, flour, milk, and cheese.</p><p>3. Mix pasta, diced ham, and cheese sauce in a baking dish.</p><p>4. Bake at 375°F for 25-30 minutes.</p>',
        'picture': f'9d827552970a108cc0962018da7b4615e65047ed8cae05407925661dc85e9432.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'casserole_cook',
        'user_created_id': 10004,
        'type': 'Premium',
        'calories': 500,
        'prep_time': 45
    },
    {
        'name': 'Pizza',
        'ingredients': 'Pizza Dough,Tomato Sauce,Mozzarella Cheese,Toppings (e.g., Pepperoni, Mushrooms, Bell Peppers)',
        'instructions': '<p>1. Preheat oven to 475°F.</p><p>2. Roll out pizza dough on a floured surface.</p><p>3. Spread tomato sauce over the dough.</p><p>4. Add mozzarella cheese and desired toppings.</p><p>5. Bake for 12-15 minutes or until the crust is golden brown.</p>',
        'picture': f'7d7b44040e2cc6b76516b930be01b370e14d6345f405f3e7646532ddecaff98b.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'pizza_enthusiast',
        'user_created_id': 10005,
        'type': 'Standard',
        'calories': 300,
        'prep_time': 20
    },
    {
        'name': 'Roasted Vegetable Frittata',
        'ingredients': 'Eggs,Assorted Vegetables (e.g., Bell Peppers, Zucchini, Tomatoes),Cheese,Oil,Herbs',
        'instructions': '<p>1. Preheat oven to 375°F.</p><p>2. Sauté vegetables in a skillet with oil.</p><p>3. Whisk eggs and pour over vegetables.</p><p>4. Sprinkle cheese and herbs on top.</p><p>5. Transfer to the oven and bake for 20-25 minutes.</p>',
        'picture': f'495fe3f7d802654e3c33efae944c25a7f6353c759f9bcb198a944adfe58421a3.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'frittata_fan',
        'user_created_id': 10006,
        'type': 'Premium',
        'calories': 250,
        'prep_time': 30
    },
    {
        'name': 'Shepherd’s Pie',
        'ingredients': 'Ground Beef,Onion,Carrots,Peas,Potatoes,Butter,Milk',
        'instructions': '<p>1. Cook ground beef with onions and carrots until browned.</p><p>2. Add peas and cook for a few more minutes.</p><p>3. Mash potatoes with butter and milk.</p><p>4. Layer beef mixture in a baking dish, top with mashed potatoes.</p><p>5. Bake at 400°F for 20-25 minutes.</p>',
        'picture': f'd17418a5ababaa12806450cc0176d46710f79349dc977b8f7e41e2f3547c556a.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'pie_baker',
        'user_created_id': 10007,
        'type': 'Private',
        'calories': 400,
        'prep_time': 40
    },
    {
        'name': 'Tacos al Pastor',
        'ingredients': 'Pork,Onion,Pineapple,Corn Tortillas,Cilantro,Lime,Chili Powder,Garlic Powder,Oregano,Salt',
        'instructions': '<p>1. Marinate pork in chili powder, garlic powder, oregano, and salt.</p><p>2. Cook pork with onions and pineapple until tender.</p><p>3. Warm tortillas and fill with pork mixture.</p><p>4. Top with cilantro and a squeeze of lime.</p>',
        'picture': f'bfd9a66641a2c90a51fbe0301dfe9ee2df6fbc90ea7f164bdba7cf4cf964f161.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'taco_king',
        'user_created_id': 33445,
        'type': 'Private',
        'calories': 320,
        'prep_time': 25
    },
    {
        'name': 'Ratatouille',
        'ingredients': 'Eggplant,Zucchini,Tomato,Bell Peppers,Onion,Garlic,Herbs,Olive Oil',
        'instructions': '<p>1. Sauté onions and garlic in olive oil.</p><p>2. Add diced eggplant, zucchini, bell peppers, and tomatoes.</p><p>3. Cook until vegetables are tender.</p><p>4. Season with herbs, salt, and pepper.</p><p>5. Serve hot.</p>',
        'picture': f'7bdece723c3f044b385ba69cee2f983e2abc3caa6bff63a8f17f136e8c811e93.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'veggie_chef',
        'user_created_id': 10008,
        'type': 'Standard',
        'calories': 150,
        'prep_time': 30
    },
    {
        'name': 'Vegetarian Pasta Primavera',
        'ingredients': 'Pasta,Assorted Vegetables (e.g., Bell Peppers, Tomatoes, Broccoli),Olive Oil,Garlic,Parmesan Cheese',
        'instructions': '<p>1. Cook pasta according to package instructions.</p><p>2. Sauté vegetables and garlic in olive oil.</p><p>3. Toss cooked pasta with vegetables and cheese.</p><p>4. Serve with extra Parmesan if desired.</p>',
        'picture': f'402c00287e07ba01097fe68f326b39b6b0ecaa95aa5f2a590f27084d79906ddc.jpg',
        'date_created': datetime.datetime.utcnow(),
        'user_created': 'pasta_love',
        'user_created_id': 10009,
        'type': 'Standard',
        'calories': 250,
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
        user_created_id = i['user_created_id']
        recipe_type = i['type']
        calories = i['calories']
        prep_time = i['prep_time']
        new_recipe = Recipe(name=name, ingredients=ingredients, instructions=instructions, picture=picture, user_created=user_created, user_created_id=user_created_id, type=recipe_type, calories=calories,
                            prep_time=prep_time)
        db.session.add(new_recipe)
        db.session.commit()
        print(f"Recipe {name} added to database")

    source_directory = 'app/static/images/images_recipe_populate'
    destination_directory = 'app/static/images_recipe'
    copy_directory(source_directory, destination_directory)


