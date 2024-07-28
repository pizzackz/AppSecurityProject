import logging
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from app.models import db, Admin, Member, MenuItem, MasterKey


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("flask_app")


# Generalised function to create all tables & seed database
def seed_database():
    """Create all database tables and seed the database with test data."""
    db.create_all()
    # create_menu_items()
    # create_fake_master_keys(5)
    create_admins()
    # create_members()
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


# Create test data for menu items
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
        # Create sample menu items
        sample_items = [
            MenuItem(
                name="Shrimp Fried Rice",
                description="A quick and easy Chinese dish with stir-fried rice, vegetables, and shrimp. Perfect for a delicious weeknight meal.",
                image="https://images.getrecipekit.com/20220904024717-shrimp-20fried-20rice.png?aspect_ratio=4:3&quality=90&",
                ingredient_list="Rice, Shrimp, Eggs, Peas, Carrots, Giner, Garlic",
            ),
            MenuItem(
                name="Pad Thai",
                description="A classic Thai stir-fried noodle dish with a perfect balance of sweet, sour, and savory flavors. Topped with peanuts and lime for a delicious finish.",
                image="https://hips.hearstapps.com/hmg-prod/images/pad-thai-index-6477629462a38.jpg?crop=0.6666666666666666xw:1xh;center,top&resize=1200:*",
                ingredient_list="Rice noodles, Shrimp, Tofu, Bean sprouts, Eggs, Peanuts, Lime, Tamarind paste, Fish sauce, Green onions",
            ),
            MenuItem(
                name="Teriyaki Chicken",
                description="A popular Japanese dish with tender chicken glazed in a sweet and savory teriyaki sauce. Served with rice and vegetables.",
                image="https://hips.hearstapps.com/delish/assets/17/26/1498598755-teriyaki-chicken.jpg?crop=1.00xw:0.844xh;0,0.0577xh",
                ingredient_list="Chicken, Soy sauce, Mirin, Sugar, Garlic, Ginger, Rice, Broccoli, Carrots",
            ),
            MenuItem(
                name="Grilled Chicken Salad",
                description=" A healthy and refreshing salad featuring grilled chicken breast, mixed greens, and a variety of fresh vegetables, topped with a light vinaigrette.",
                image="https://sundaysuppermovement.com/wp-content/uploads/2021/06/grilled-chicken-salad-1.jpg",
                ingredient_list="Chicken, Mixed greens(lettuce, spinach, arugula), Tomatoes, Cucumbers, Red onions, Vinaigrette",
            ),
            MenuItem(
                name="Chicken Porridge",
                description="A comforting and nutritious chicken porridge made with simple ingredients. Perfect for a warm, hearty meal.",
                image="https://omnivorescookbook.com/wp-content/uploads/2022/11/221116_Chicken-Congee_550.jpg",
                ingredient_list="Chicken, Rice, Chicken Broth, Ginger, Garlic, Green onions",
            ),
            MenuItem(
                name="Baked Sweet Potato and Black Bean Tacos",
                description="Tacos filled with roasted sweet potatoes and black beans, topped with avocado and a squeeze of lime. A delicious and healthy meal!",
                image="https://www.eatingwell.com/thmb/DTva0yAWTc2hW3q1jp_XnoBNskA=/1500x0/filters:no_upscale():max_bytes(150000):strip_icc()/sweet-potato-black-bean-tacos-63cda3afd6324c5395a547c28bb3da1e.jpg",
                ingredient_list="Sweet potatoes, Black beans, Cumin, Chili powder, Tortillas, Avocado, Lime",
            ),
            MenuItem(
                name="Tomato Basil Pasta",
                description="A simple and flavorful pasta dish with fresh tomatoes, basil, and garlic, tossed with olive oil and parmesan cheese.",
                image="https://frommybowl.com/wp-content/uploads/2022/07/Spicy_Tomato_Basil_Pasta_Vegan_FromMyBowl-12.jpg",
                ingredient_list="Pasta, Tomatoes, Basil, Garlic, Parmesan cheese",
            ),
            MenuItem(
                name="Frikadeller (Danish Meatballs)",
                description="Traditional Danish meatballs made with ground pork(not included in this recipe) and beef, seasoned with onions and spices. Served with boiled potatoes, gravy, and red cabbage or pickled cucumbers.",
                image="https://www.gutekueche.ch/upload/rezept/18571/1600x1200_daenische-frikadeller.jpg",
                ingredient_list="Ground beef, Onion, Eggs, Milk, Breadcrumbs, Allspice,  Potatoes, Gravy, Red cabbage, Pickled cucumbers",
            ),
            MenuItem(
                name="Vegetable Stir-Fry with Tofu",
                description=" A quick and healthy stir-fry loaded with fresh vegetables and seasoned with soy sauce and garlic. Perfect served over rice or noodles.",
                image="https://www.lastingredient.com/wp-content/uploads/2021/02/ginger-garlic-veggie-tofu-stir-fry7.jpg",
                ingredient_list="Tofu, Broccoli florets, Red bell pepper, Carrot, Zucchini, Snap peas, Garlic",
            ),
        ]

        # Add the sample items to the session
        db.session.bulk_save_objects(sample_items)

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
        logger.info("Members test data added!")
    else:
        logger.info("Members test data already exists.")
