import logging

from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import MenuItem, Order, OrderItem
from app import db
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
            MenuItem(name='Shrimp Fried Rice',
                     description='A quick and easy Chinese dish with stir-fried rice, vegetables, and shrimp. Perfect for a delicious weeknight meal.',
                     image='https://images.getrecipekit.com/20220904024717-shrimp-20fried-20rice.png?aspect_ratio=4:3&quality=90&',
                     ingredient_list='Rice, Shrimp, Eggs, Peas, Carrots, Giner, Garlic'),
            MenuItem(name='Pad Thai',
                     description='A classic Thai stir-fried noodle dish with a perfect balance of sweet, sour, and savory flavors. Topped with peanuts and lime for a delicious finish.',
                     image='https://hips.hearstapps.com/hmg-prod/images/pad-thai-index-6477629462a38.jpg?crop=0.6666666666666666xw:1xh;center,top&resize=1200:*',
                     ingredient_list='Rice noodles, Shrimp, Tofu, Bean sprouts, Eggs, Peanuts, Lime, Tamarind paste, Fish sauce, Green onions'),
            MenuItem(name='Teriyaki Chicken',
                     description='A popular Japanese dish with tender chicken glazed in a sweet and savory teriyaki sauce. Served with rice and vegetables.',
                     image='https://hips.hearstapps.com/delish/assets/17/26/1498598755-teriyaki-chicken.jpg?crop=1.00xw:0.844xh;0,0.0577xh',
                     ingredient_list='Chicken, Soy sauce, Mirin, Sugar, Garlic, Ginger, Rice, Broccoli, Carrots'),
            MenuItem(name='Grilled Chicken Salad',
                     description=' A healthy and refreshing salad featuring grilled chicken breast, mixed greens, and a variety of fresh vegetables, topped with a light vinaigrette.',
                     image='https://sundaysuppermovement.com/wp-content/uploads/2021/06/grilled-chicken-salad-1.jpg',
                     ingredient_list='Chicken, Mixed greens(lettuce, spinach, arugula), Tomatoes, Cucumbers, Red onions, Vinaigrette'),
            MenuItem(name='Chicken Porridge',
                     description='A comforting and nutritious chicken porridge made with simple ingredients. Perfect for a warm, hearty meal.',
                     image='https://omnivorescookbook.com/wp-content/uploads/2022/11/221116_Chicken-Congee_550.jpg',
                     ingredient_list='Chicken, Rice, Chicken Broth, Ginger, Garlic, Green onions'),
            MenuItem(name='Baked Sweet Potato and Black Bean Tacos',
                     description='Tacos filled with roasted sweet potatoes and black beans, topped with avocado and a squeeze of lime. A delicious and healthy meal!',
                     image='https://www.eatingwell.com/thmb/DTva0yAWTc2hW3q1jp_XnoBNskA=/1500x0/filters:no_upscale():max_bytes(150000):strip_icc()/sweet-potato-black-bean-tacos-63cda3afd6324c5395a547c28bb3da1e.jpg',
                     ingredient_list='Sweet potatoes, Black beans, Cumin, Chili powder, Tortillas, Avocado, Lime'),
            MenuItem(name='Tomato Basil Pasta',
                     description='A simple and flavorful pasta dish with fresh tomatoes, basil, and garlic, tossed with olive oil and parmesan cheese.',
                     image='https://frommybowl.com/wp-content/uploads/2022/07/Spicy_Tomato_Basil_Pasta_Vegan_FromMyBowl-12.jpg',
                     ingredient_list='Pasta, Tomatoes, Basil, Garlic, Parmesan cheese'),
            MenuItem(name='Frikadeller (Danish Meatballs)',
                     description='Traditional Danish meatballs made with ground pork(not included in this recipe) and beef, seasoned with onions and spices. Served with boiled potatoes, gravy, and red cabbage or pickled cucumbers.',
                     image='https://www.gutekueche.ch/upload/rezept/18571/1600x1200_daenische-frikadeller.jpg',
                     ingredient_list='Ground beef, Onion, Eggs, Milk, Breadcrumbs, Allspice,  Potatoes, Gravy, Red cabbage, Pickled cucumbers'),
            MenuItem(name='Vegetable Stir-Fry with Tofu',
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


def alter_menu_item_table():
    # with db.engine.connect() as conn:
    #     conn.execute(text('ALTER TABLE menu_items ADD COLUMN image VARCHAR(255)'))
    #     conn.execute(text('ALTER TABLE menu_items ADD COLUMN ingredient_list TEXT'))
    pass


@member_order_bp.route('/home', methods=['POST', 'GET'])
def home():
    return render_template('member/transaction-processing/index.html')


@member_order_bp.route('/menu')
def menu():
    items = MenuItem.query.all()
    return render_template('member/order/menu.html', menu_items=items)


@member_order_bp.route('/order', methods=['POST'])
def order():
    customer_name = request.form['customer_name']
    customer_email = request.form['customer_email']
    item_ids = request.form.getlist('item_id')
    quantities = request.form.getlist('quantity')

    if not item_ids or not quantities or not customer_name:
        flash('Please fill in all required fields.')
        return redirect(url_for('ordering_bp.menu'))

    order = Order(customer_name=customer_name, customer_email=customer_email)
    db.session.add(order)
    db.session.commit()

    for item_id, quantity in zip(item_ids, quantities):
        order_item = OrderItem(order_id=order.id, menu_item_id=item_id, quantity=quantity)
        db.session.add(order_item)

    db.session.commit()

    flash('Order placed successfully!')
    return redirect(url_for('ordering_bp.menu'))


@member_order_bp.route('/orders')
def orders():
    orders = Order.query.all()
    return render_template('member/order/orders.html', orders=orders)


