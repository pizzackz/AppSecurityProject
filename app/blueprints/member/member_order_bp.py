import logging

from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import MenuItem, Order, OrderItem
from app.forms import OrderForm, MenuForm
from app import db, csrf
from sqlalchemy import text


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('flask_app')

# Create blueprint
member_order_bp = Blueprint('member_order_bp', __name__)

from app.models import MenuItem, db


# Adding test data to the database
def add_test_data():
    # Clear the database to avoid duplicate entries
    try:
        num_rows_deleted = db.session.query(MenuItem).delete()
        db.session.commit()
        print(f"Deleted {num_rows_deleted} rows from the MenuItem table.")
    except Exception as e:
        db.session.rollback()
        print(f"An error occurred while clearing the MenuItem table: {e}")


    # Check if the test data already exists to avoid duplicate entries
    if MenuItem.query.count() == 0:
        # Create sample menu items
        sample_items = [
            MenuItem(id=1836,
                    name='Shrimp Fried Rice',
                     description='A quick and easy Chinese dish with stir-fried rice, vegetables, and shrimp. Perfect for a delicious weeknight meal.',
                     image='https://images.getrecipekit.com/20220904024717-shrimp-20fried-20rice.png?aspect_ratio=4:3&quality=90&',
                     ingredient_list='Rice, Shrimp, Eggs, Peas, Carrots, Giner, Garlic'),
            MenuItem(id=4296,
                    name='Pad Thai',
                     description='A classic Thai stir-fried noodle dish with a perfect balance of sweet, sour, and savory flavors. Topped with peanuts and lime for a delicious finish.',
                     image='https://hips.hearstapps.com/hmg-prod/images/pad-thai-index-6477629462a38.jpg?crop=0.6666666666666666xw:1xh;center,top&resize=1200:*',
                     ingredient_list='Rice noodles, Shrimp, Tofu, Bean sprouts, Eggs, Peanuts, Lime, Tamarind paste, Fish sauce, Green onions'),
            MenuItem(id=5912,
                    name='Teriyaki Chicken',
                     description='A popular Japanese dish with tender chicken glazed in a sweet and savory teriyaki sauce. Served with rice and vegetables.',
                     image='https://hips.hearstapps.com/delish/assets/17/26/1498598755-teriyaki-chicken.jpg?crop=1.00xw:0.844xh;0,0.0577xh',
                     ingredient_list='Chicken, Soy sauce, Mirin, Sugar, Garlic, Ginger, Rice, Broccoli, Carrots'),
            MenuItem(id=2653,
                     name='Grilled Chicken Salad',
                     description=' A healthy and refreshing salad featuring grilled chicken breast, mixed greens, and a variety of fresh vegetables, topped with a light vinaigrette.',
                     image='https://sundaysuppermovement.com/wp-content/uploads/2021/06/grilled-chicken-salad-1.jpg',
                     ingredient_list='Chicken, Mixed greens(lettuce, spinach, arugula), Tomatoes, Cucumbers, Red onions, Vinaigrette'),
            MenuItem(id=8371,
                     name='Chicken Porridge',
                     description='A comforting and nutritious chicken porridge made with simple ingredients. Perfect for a warm, hearty meal.',
                     image='https://omnivorescookbook.com/wp-content/uploads/2022/11/221116_Chicken-Congee_550.jpg',
                     ingredient_list='Chicken, Rice, Chicken Broth, Ginger, Garlic, Green onions'),
            MenuItem(id=4905,
                     name='Baked Sweet Potato and Black Bean Tacos',
                     description='Tacos filled with roasted sweet potatoes and black beans, topped with avocado and a squeeze of lime. A delicious and healthy meal!',
                     image='https://www.eatingwell.com/thmb/DTva0yAWTc2hW3q1jp_XnoBNskA=/1500x0/filters:no_upscale():max_bytes(150000):strip_icc()/sweet-potato-black-bean-tacos-63cda3afd6324c5395a547c28bb3da1e.jpg',
                     ingredient_list='Sweet potatoes, Black beans, Cumin, Chili powder, Tortillas, Avocado, Lime'),
            MenuItem(id=1034,
                     name='Tomato Basil Pasta',
                     description='A simple and flavorful pasta dish with fresh tomatoes, basil, and garlic, tossed with olive oil and parmesan cheese.',
                     image='https://frommybowl.com/wp-content/uploads/2022/07/Spicy_Tomato_Basil_Pasta_Vegan_FromMyBowl-12.jpg',
                     ingredient_list='Pasta, Tomatoes, Basil, Garlic, Parmesan cheese'),
            MenuItem(id=6975,
                     name='Frikadeller (Danish Meatballs)',
                     description='Traditional Danish meatballs made with ground pork(not included in this recipe) and beef, seasoned with onions and spices. Served with boiled potatoes, gravy, and red cabbage or pickled cucumbers.',
                     image='https://www.gutekueche.ch/upload/rezept/18571/1600x1200_daenische-frikadeller.jpg',
                     ingredient_list='Ground beef, Onion, Eggs, Milk, Breadcrumbs, Allspice,  Potatoes, Gravy, Red cabbage, Pickled cucumbers'),
            MenuItem(id=5642,
                     name='Vegetable Stir-Fry with Tofu',
                     description=' A quick and healthy stir-fry loaded with fresh vegetables and seasoned with soy sauce and garlic. Perfect served over rice or noodles.',
                     image='https://www.lastingredient.com/wp-content/uploads/2021/02/ginger-garlic-veggie-tofu-stir-fry7.jpg',
                     ingredient_list='Tofu, Broccoli florets, Red bell pepper, Carrot, Zucchini, Snap peas, Garlic'),
        ]

        # Add the sample items to the session
        db.session.bulk_save_objects(sample_items)

        # Commit the session to the database
        db.session.commit()
        print("Test data added!")
    else:
        print("Test data already exists.")

#Both Alters are temporary and used for debugging purposes
def alter_menu_item_table():
    # with db.engine.connect() as conn:
    #     conn.execute(text('ALTER TABLE menu_items ADD COLUMN image VARCHAR(255)'))
    #     conn.execute(text('ALTER TABLE menu_items ADD COLUMN ingredient_list TEXT'))
    pass


def alter_order_table():
    # with db.engine.connect() as conn:
    #     #Checking the columns in the orders table
    #     result = conn.execute(text("SHOW COLUMNS FROM orders"))
    #     for row in result:
    #         print(row)
        # Adding new columns to the orders table
        # conn.execute(text("""
        #     ALTER TABLE orders
        #     ADD COLUMN address VARCHAR(255) NOT NULL,
        #     ADD COLUMN postal_code VARCHAR(20) NOT NULL,
        #     ADD COLUMN phone_number VARCHAR(20) NOT NULL,
        #     ADD COLUMN delivery_date VARCHAR(20) NOT NULL,
        #     ADD COLUMN delivery_time VARCHAR(20) NOT NULL
        # """))
        pass


@member_order_bp.route('/home', methods=['POST', 'GET'])
def home():
    return render_template('member/transaction-processing/index.html')


@member_order_bp.route('/menu', methods=['POST', 'GET'])
def menu():
    form = MenuForm()
    items = MenuItem.query.all()

    if request.method == "POST":
        selected_items = request.form.getlist('menu_item_id')
        return redirect(url_for('member_order_bp.order', selected_items=selected_items))

    return render_template('member/order/menu.html', menu_items=items, form=form)


@member_order_bp.route('/order', methods=['GET', 'POST'])
def order():
    form = OrderForm()

    selected_items = request.args.getlist('selected_items')
    items = MenuItem.query.filter(MenuItem.id.in_(selected_items)).all()

    if form.validate_on_submit():
        new_order = Order(
            customer_name=form.name.data,
            address=form.address.data,
            postal_code=form.postal_code.data,
            phone_number=form.phone_number.data,
            delivery_date=form.selected_date.data,
            delivery_time=form.selected_time.data
        )
        db.session.add(new_order)
        db.session.commit()

        for item in items:
            order_item = OrderItem(
                order_id=new_order.id,
                menu_item_id=item.id,
                quantity=1  # Assuming a default quantity of 1 for simplicity
            )
            db.session.add(order_item)
        db.session.commit()

        return redirect(url_for('member_order_bp.success'))
    else:
        flash('Please fill in all the required fields.', 'danger')
        print(form.errors)

    return render_template('member/order/orders.html', form=form, menu_items=items)



@member_order_bp.route('/order_confirm', methods=['POST', 'GET'])
def success():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('member_subscription_bp.home'))
    return render_template('member/order/success.html')

