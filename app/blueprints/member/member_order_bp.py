import logging
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import MenuItem, Order, OrderItem
from app.forms.forms import OrderForm, MenuForm
from app import db, csrf
from sqlalchemy.exc import SQLAlchemyError
from app.utils import clean_input, get_session_data, set_session_data, clear_session_data
import json
import atexit
from datetime import datetime, timedelta
from flask_login import login_required, current_user

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


# Define a custom filter to escape JavaScript strings
@member_order_bp.app_template_filter('escapejs')
def escapejs_filter(value):
    return json.dumps(value)  # Use json.dumps to escape the string for JavaScript


# Ensure all handlers are flushed and closed properly at the end of the application
@atexit.register
def shutdown_logging():
    for handler in logger.handlers:
        handler.flush()
        handler.close()


# Force the browser to always fetch the latest version of the page
@member_order_bp.after_request
def add_no_cache_headers(response):
    response.cache_control.no_store = True
    response.cache_control.no_cache = True
    response.cache_control.must_revalidate = True
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Order Blueprint

@member_order_bp.route('/menu', methods=['POST', 'GET'])
@login_required
def menu():
    form = MenuForm()
    items = MenuItem.query.all()

    if request.method == "POST":
        selected_items = request.form.getlist('menu_item_id')
        set_session_data({'selected_items': selected_items})
        return redirect(url_for('member_order_bp.booking', selected_items=selected_items))

    return render_template('member/order/menu.html', menu_items=items, form=form)


@member_order_bp.route('/booking', methods=['GET', 'POST'])
@login_required
def booking():
    form = OrderForm()

    # Retrieve session data
    try:
        session_data = get_session_data(['selected_items'])
        selected_items = [item for item in session_data.get('selected_items', []) if item]

        # Security check: Ensure the user has selected items from the menu
        if not selected_items:
            flash("An error occurred while processing your request. Please try again.", "error")
            return redirect(url_for('member_order_bp.menu'))
        # Security check: Ensure the user has completed the menu step
    except TypeError as t:
        logger.error(f"Invalid session data: {t}")
        flash("An error occurred while processing your request. Please try again.", "error")
        return redirect(url_for('member_order_bp.menu'))



        return redirect(url_for('member_order_bp.menu'))

    if request.method == 'POST':
        if request.form.get('return') == 'True':
            return redirect(url_for('member_order_bp.menu'))
        # Handle form submission
        delivery_date = request.form.get('delivery_date')
        delivery_time = request.form.get('delivery_time')

        # Perform server-side validation
        try:
            delivery_date_obj = datetime.strptime(delivery_date, '%Y-%m-%d')
            if delivery_date_obj < datetime.now():
                flash('The delivery date cannot be in the past.', 'error')
                return redirect(url_for('member_order_bp.booking'))
            elif delivery_date_obj > (datetime.now() + timedelta(days=(30 - datetime.now().day + 30))):
                flash('The delivery date cannot be beyond the end of next month.', 'error')
                return redirect(url_for('member_order_bp.booking'))
        except ValueError:
            flash('Delivery date not specified.', 'error')

        # Save data to session
        set_session_data({
            'selected_items': [item for item in request.args.getlist('selected_items') if item],
            'delivery_date': delivery_date,
            'delivery_time': delivery_time
        })

        return redirect(url_for('member_order_bp.order'))

    return render_template('member/order/booking.html', form=form)


@member_order_bp.route('/order', methods=['GET', 'POST'])
@login_required
def order():
    form = OrderForm()

    # Retrieve session data
    try:
        session_data = get_session_data(['selected_items', 'delivery_date', 'delivery_time'])
        selected_items = [item for item in session_data.get('selected_items', []) if item]
        delivery_date = session_data.get('delivery_date')
        delivery_time = session_data.get('delivery_time')
    except TypeError as t:
        logger.error(f"Invalid session data: {t}")
        flash("An error occurred while processing your request. Please try again.", "error")
        return redirect(url_for('member_order_bp.menu'))

    # Security check: Ensure the user has completed the booking step
    if 'delivery_date' not in session_data or 'delivery_time' not in session_data:
        flash('Please complete the booking step first.', 'error')
        return redirect(url_for('member_order_bp.booking'))

    # Pre-fill the form with session data
    form.selected_date.data = delivery_date
    form.selected_time.data = delivery_time
    form.selected_items.data = selected_items

    if not selected_items or not delivery_date or not delivery_time:
        flash('Please select items from the menu and choose a delivery date and time.', 'error')
        return redirect(url_for('member_order_bp.menu'))

    try:
        # Cleaning inputs + Parameterized Queries
        items = MenuItem.query.filter(MenuItem.id.in_(selected_items)).all()
    except SQLAlchemyError as e:
        logger.error(f"Database error when querying menu items: {e}")
        flash("An error occurred while processing your request. Please try again.", "error")
        return redirect(url_for('member_order_bp.menu'))

    if request.method == 'POST' and form.validate_on_submit():
        try:
            new_order = Order(
                user_id=current_user.id,
                customer_name=form.name.data,
                address=form.address.data,
                postal_code=form.postal_code.data,
                phone_number=form.phone_number.data,
                delivery_date=form.selected_date.data,
                delivery_time=form.selected_time.data,
                selected_items=form.selected_items.data,
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
            print(f"Order {new_order.id} created successfully for customer {new_order.customer_name}.")
            clear_session_data(['selected_items', 'delivery_date', 'delivery_time'])
            return redirect(url_for('member_order_bp.success'))

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error when creating order: {e}")
            flash("An error occurred while creating your order. Please try again.", "danger")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            flash("An unexpected error occurred. Please try again.", "danger")

        return redirect(url_for('member_order_bp.success'))

    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in the {getattr(form, field).label.text} field - {error}", 'error')
        logger.warning(f"Order form validation failed: {form.errors}")
        flash('Please fill in all the required fields and captcha.', 'error')

    return render_template('member/order/orders.html', form=form, menu_items=items)


@member_order_bp.route('/order_confirm', methods=['POST', 'GET'])
@login_required
def success():
    clear_session_data(['selected_items', 'delivery_date', 'delivery_time'])
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('home_bp.home'))
    return render_template('member/order/success.html')


# Order History Blueprint
@member_order_bp.route('/order_history', methods=['GET'])
@login_required
def order_history():
    # Fetch orders for the current user
    user_id = current_user.id  # Assuming the user is logged in and `current_user` is set
    orders = Order.query.filter_by(user_id=user_id).all()

    # Fetch menu item details for each order
    for order in orders:
        item_ids = order.selected_items
        order.items_details = MenuItem.query.filter(MenuItem.id.in_(item_ids)).all()
        order.formatted_date = order.created_at.strftime("%b %d, %I:%M %p")

    return render_template('member/order/order_history.html', orders=orders)