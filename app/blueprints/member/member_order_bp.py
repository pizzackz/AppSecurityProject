import logging
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import MenuItem, Order, OrderItem
from app.forms.forms import OrderForm, MenuForm
from app import db, csrf
from sqlalchemy.exc import SQLAlchemyError
from app.utils import clean_input
import json
import atexit

# Create a logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Set up logging to a file
log_file_path = os.path.join('app/blueprints/member/logs', 'app.log')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('flask_app')

# Check if handlers are already added
if not logger.handlers:
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Ensure the default logging to the console remains
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

# Create blueprint
member_order_bp = Blueprint('member_order_bp', __name__)

from app.models import MenuItem, db

#Define a custom filter to escape JavaScript strings
@member_order_bp.app_template_filter('escapejs')
def escapejs_filter(value):
    return json.dumps(value)  # Use json.dumps to escape the string for JavaScript

# Ensure all handlers are flushed and closed properly at the end of the application
@atexit.register
def shutdown_logging():
    for handler in logger.handlers:
        handler.flush()
        handler.close()


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

    try:
        # Cleaning inputs + Parameterized Queries
        selected_items = [clean_input(item) for item in request.args.getlist('selected_items')]
        items = MenuItem.query.filter(MenuItem.id.in_(selected_items)).all()
    except SQLAlchemyError as e:
        logger.error(f"Database error when querying menu items: {e}")
        flash("An error occurred while processing your request. Please try again.", "error")
        return redirect(url_for('member_order_bp.menu'))

    if form.validate_on_submit():
        try:
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
                    quantity=1
                )
                db.session.add(order_item)
            db.session.commit()

            logger.info(f"Order {new_order.id} created successfully for customer {new_order.customer_name}.")
            return redirect(url_for('member_order_bp.success'))
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error when creating order: {e}")
            flash("An error occurred while creating your order. Please try again.", "danger")

        return redirect(url_for('member_order_bp.success'))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in the {getattr(form, field).label.text} field - {error}", 'error')
        logger.warning(f"Order form validation failed: {form.errors}")
        flash('Please fill in all the required fields.', 'error')

    return render_template('member/order/orders.html', form=form, menu_items=items)


@member_order_bp.route('/order_confirm', methods=['POST', 'GET'])
def success():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('member_subscription_bp.home'))
    return render_template('member/order/success.html')

