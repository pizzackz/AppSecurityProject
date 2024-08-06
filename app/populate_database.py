import logging
import os
from datetime import datetime, timedelta, timezone
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from app.models import db, Admin, Member, MenuItem, MasterKey, Log_general, Log_account, Log_transaction, User
from faker import Faker


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tastefully")


# Generalised function to create all tables & seed database
def seed_database():
    """Create all database tables and seed the database with test data."""
    db.create_all()
    create_menu_items()
    create_fake_master_keys(3)
    create_admins()
    create_members()
    create_fake_logs(Log_transaction, 20)
    create_fake_logs(Log_account, 20)
    create_fake_logs(Log_general, 20)
    logging.info("Database initialised and test data added.")


# Create fake master keys for simplicity, remove them later
def create_fake_master_keys(num_keys=5):
    """
    Generate a specified number of fake master keys with a 30-day expiration.
    
    Args:
        num_keys (int): Number of fake master keys to generate.
    """
    try:
        for _ in range(num_keys):
            new_key = MasterKey.generate_master_key()
            db.session.add(new_key)

        db.session.commit()
        print(f"Successfully created {num_keys} fake master keys.")
    except Exception as e:
        db.session.rollback()
        print(f"Error creating fake master keys: {e}")


def create_menu_items():
    """Create test data for menu items."""
    # Clear the database to avoid duplicate entries
    try:
        num_rows_deleted = db.session.query(MenuItem).delete()
        db.session.commit()
        logger.info(f"Deleted {num_rows_deleted} rows from MenuItem table.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"An error occurred while clearing MenuItem table: {e}")

    # Check if the test data already exists to avoid duplicate entries
    if MenuItem.query.count() == 0:
        # Define the base path for the images
        base_path = os.path.join(os.path.dirname(__file__), 'static', 'images', 'menu_items')
        # Create sample menu items
        sample_items_data = [
            {
                "name": "Shrimp Fried Rice",
                "description": "A quick and easy Chinese dish with stir-fried rice, vegetables, and shrimp. Perfect for a delicious weeknight meal.",
                "image_path": os.path.join(base_path, "shrimp_fried_rice.png"),
                "ingredient_list": "Rice, Shrimp, Eggs, Peas, Carrots, Ginger, Garlic",
            },
            {
                "name": "Pad Thai",
                "description": "A classic Thai stir-fried noodle dish with a perfect balance of sweet, sour, and savory flavors. Topped with peanuts and lime for a delicious finish.",
                "image_path": os.path.join(base_path, "pad_thai.png"),
                "ingredient_list": "Rice noodles, Shrimp, Tofu, Bean sprouts, Eggs, Peanuts, Lime, Tamarind paste, Fish sauce, Green onions",
            },
            {
                "name": "Teriyaki Chicken",
                "description": "A popular Japanese dish with tender chicken glazed in a sweet and savory teriyaki sauce. Served with rice and vegetables.",
                "image_path": os.path.join(base_path, "teriyaki_chicken.png"),
                "ingredient_list": "Chicken, Soy sauce, Mirin, Sugar, Garlic, Ginger, Rice, Broccoli, Carrots",
            },
            {
                "name": "Grilled Chicken Salad",
                "description": " A healthy and refreshing salad featuring grilled chicken breast, mixed greens, and a variety of fresh vegetables, topped with a light vinaigrette.",
                "image_path": os.path.join(base_path, "chicken_salad.png"),
                "ingredient_list": "Chicken, Mixed greens(lettuce, spinach, arugula), Tomatoes, Cucumbers, Red onions, Vinaigrette",
            },
            {
                "name": "Chicken Porridge",
                "description": "A comforting and nutritious chicken porridge made with simple ingredients. Perfect for a warm, hearty meal.",
                "image_path": os.path.join(base_path, "chicken_porridge.png"),
                "ingredient_list": "Chicken, Rice, Chicken Broth, Ginger, Garlic, Green onions",
            },
            {
                "name": "Baked Sweet Potato and Black Bean Tacos",
                "description": "Tacos filled with roasted sweet potatoes and black beans, topped with avocado and a squeeze of lime. A delicious and healthy meal!",
                "image_path": os.path.join(base_path, "sweet_potato_black_bean_tacos.png"),
                "ingredient_list": "Sweet potatoes, Black beans, Cumin, Chili powder, Tortillas, Avocado, Lime",
            },
            {
                "name": "Tomato Basil Pasta",
                "description": "A simple and flavorful pasta dish with fresh tomatoes, basil, and garlic, tossed with olive oil and parmesan cheese.",
                "image_path": os.path.join(base_path, "tomato_basil_pasta.png"),
                "ingredient_list": "Pasta, Tomatoes, Basil, Garlic, Parmesan cheese",
            },
            {
                "name": "Frikadeller (Danish Meatballs)",
                "description": "Traditional Danish meatballs made with ground pork(not included in this recipe) and beef, seasoned with onions and spices. Served with boiled potatoes, gravy, and red cabbage or pickled cucumbers.",
                "image_path": os.path.join(base_path, "frikadeller.png"),
                "ingredient_list": "Ground beef, Onion, Eggs, Milk, Breadcrumbs, Allspice, Potatoes, Gravy, Red cabbage, Pickled cucumbers",
            },
            {
                "name": "Vegetable Stir-Fry with Tofu",
                "description": " A quick and healthy stir-fry loaded with fresh vegetables and seasoned with soy sauce and garlic. Perfect served over rice or noodles.",
                "image_path": os.path.join(base_path, "tofu_stir_fry.png"),
                "ingredient_list": "Tofu, Broccoli florets, Red bell pepper, Carrot, Zucchini, Snap peas, Garlic",
            },
        ]

        menu_items = []
        for item in sample_items_data:
            image_data = None
            if "image_path" in item and os.path.exists(item["image_path"]):
                with open(item["image_path"], "rb") as image_file:
                    image_data = image_file.read()
            menu_item = MenuItem(
                name=item["name"],
                description=item["description"],
                image=image_data,
                ingredient_list=item["ingredient_list"]
            )
            menu_items.append(menu_item)

        # Add the sample items to the session
        db.session.bulk_save_objects(menu_items)

        # Commit the session to the database
        db.session.commit()
        logger.info("Menu Items test data added!")
    else:
        logger.info("Menu Items test data already exists.")


# Create test data for admins
def create_admins():
    """Create test data for admins."""
    # Clear the database to avoid duplicate entries
    try:
        admins: list[Admin] = Admin.query.all()

        for admin in admins:
            db.session.delete(admin)
        
        db.session.commit()
        logger.info(f"Deleted {len(admins)} rows from Admin table.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"An error occurred while clearing Admin table: {e}")

    # Check if the test data already exists to avoid duplicate entries
    if Admin.query.count() == 0:
        # Create sample admin
        password = "password"
        Admin.create(username="admin1", email="admin1@gmail.com", password_hash=generate_password_hash(password)),
        Admin.create(username="admin2", email="admin2@gmail.com", password_hash=generate_password_hash(password))

        # Commit the session to the database
        db.session.commit()
        logger.info("Admins test data added!")
    else:
        logger.info("Admins test data already exists.")


# Create test data for members
def create_members():
    """Create test data for members."""
    # Clear the database to avoid duplicate entries
    try:
        members = Member.query.all()

        for member in members:
            db.session.delete(member)

        db.session.commit()
        logger.info(f"Deleted {len(members)} rows from Member table.")
    except Exception as e:
        db.session.rollback()
        logger.error(f"An error occurred while clearing Member table: {e}")

    # Check if the test data already exists to avoid duplicate entries
    if Member.query.count() == 0:
        # Create sample members
        password = "password"
        hashed_password = generate_password_hash(password)

        sample_members = [
            Member.create(
                username="member1",
                email="member1@gmail.com",
                subscription_plan="premium",
                password_hash=hashed_password
            ),
            Member.create(
                username="member2",
                email="member2@gmail.com",
                subscription_plan="standard",
                password_hash=hashed_password
            ),
        ]

        # Commit the session to the database
        db.session.commit()

        sample_members[0].subscription_end_date = datetime.now(timezone.utc) + timedelta(days=30)
        db.session.commit()

        logger.info("Members test data added!")
    else:
        logger.info("Members test data already exists.")


# Create fake logs
def create_fake_logs(model, num_logs):
    fake = Faker()
    users = User.query.all()
    for _ in range(num_logs):
        log = model(
            log_datetime=fake.date_time_this_year(),
            priority_level=fake.random_element(elements=('Low', 'Medium', 'High')),
            user_id=users[fake.random_int(min=0, max=len(users)-1)].id,
            file_subdir=fake.file_path(depth=1),
            log_info=fake.sentence(nb_words=10)
        )
        db.session.add(log)
    db.session.commit()
