import logging
import os
import json
import atexit
import pendulum
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, abort
from flask_login import login_required, current_user
from sqlalchemy.exc import SQLAlchemyError
from app.models import MenuItem, Order, OrderItem
from app.forms.forms import OrderForm, MenuForm
from app import db, csrf, limiter
from app.utils import clean_input, get_session_data, set_session_data, clear_session_data, check_admin, check_premium_member, send_email
from datetime import datetime, timedelta
from io import BytesIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.models import MenuItem, db

# # Create a logs directory if it doesn't exist
# if not os.path.exists('logs'):
#     os.makedirs('logs')

# # Set up logging to a file
# log_file_path = os.path.join('app/blueprints/member/logs', 'app.log')

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger('flask_app')

# # Check if handlers are already added
# if not logger.handlers:
#     file_handler = logging.FileHandler(log_file_path)
#     file_handler.setLevel(logging.INFO)

#     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#     file_handler.setFormatter(formatter)
#     logger.addHandler(file_handler)

#     # Ensure the default logging to the console remains
#     console_handler = logging.StreamHandler()
#     console_handler.setLevel(logging.INFO)
#     console_handler.setFormatter(formatter)
#     logger.addHandler(console_handler)

logger = logging.getLogger("tastefully")

# Create blueprint
member_order_bp = Blueprint('member_order_bp', __name__)


def update_order_status(order):
    """Update the status of the order if it should be in the 'preparing' stage."""
    if order.status == 'Order Placed' and order.delivery_date == datetime.utcnow().date() + timedelta(days=1):
        order.status = 'Preparing'
        db.session.commit()


# Example: Function to retrieve the customer's last order from the database
def get_previous_order(customer_id):
    # Replace this with actual database query logic
    previous_order = {
        'name': 'John Doe',
        'address': '123 ABC Street',
        'postal_code': '123456',
        'phone_number': '9123 4567',
        'selected_date': '2024-08-10',
        'selected_time': '12:00',
        'selected_items': 'Item 1, Item 2',
    }
    return previous_order


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


# Image Renderer
@member_order_bp.route('/image/<int:item_id>')
@login_required
@limiter.exempt
def get_image(item_id):
    check = check_premium_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check
    menu_item = MenuItem.query.get(item_id)
    if not menu_item or not menu_item.image:
        abort(404)  # Not found if the menu item or image does not exist
    return send_file(BytesIO(menu_item.image), mimetype='image/jpeg', as_attachment=False, download_name=f"{menu_item.name}.jpg")


# Order Blueprint

@member_order_bp.route('/menu', methods=['POST', 'GET'])
@login_required
def menu():
    check = check_premium_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check
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
    check = check_premium_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check
    form = OrderForm()

    # Retrieve session data
    try:
        session_data = get_session_data(['selected_items'])
        selected_items = [item for item in session_data.get('selected_items', []) if item]

        # Security check: Ensure the user has selected items from the menu
        if not selected_items:
            flash("An error occurred while processing your request", "error")
            return redirect(url_for('member_order_bp.menu'))
        # Security check: Ensure the user has completed the menu step
    except TypeError as t:
        logger.error(f"Invalid session data: {t}")
        flash("An error occurred while processing your request.", "error")
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
    check = check_premium_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check
    form = OrderForm()

    # Retrieve session data
    try:
        session_data = get_session_data(['selected_items', 'delivery_date', 'delivery_time'])
        selected_items = [item for item in session_data.get('selected_items', []) if item]
        delivery_date = session_data.get('delivery_date')
        delivery_time = session_data.get('delivery_time')
    except TypeError as t:
        logger.error(f"Invalid session data: {t}")
        flash("An error occurred while processing your request.", "error")
        return redirect(url_for('member_order_bp.menu'))

    # Security check: Ensure the user has completed the booking step
    if 'delivery_date' not in session_data or 'delivery_time' not in session_data:
        flash('Please complete the booking step first.', 'error')
        return redirect(url_for('member_order_bp.booking'))

    # Storing delivery metadata from session data
    form.selected_date.data = delivery_date
    form.selected_time.data = delivery_time
    form.selected_items.data = selected_items

    # Retrieve and pre-fill data
    form.name.data = current_user.username
    if current_user.address:
        form.address.data = current_user.address
    if current_user.postal_code:
        form.postal_code.data = current_user.postal_code
    if current_user.phone_number:
        form.phone_number.data = current_user.phone_number

    if not selected_items or not delivery_date or not delivery_time:
        flash('Select item and delivery information.', 'error')
        return redirect(url_for('member_order_bp.menu'))

    try:
        # Cleaning inputs + Parameterized Queries
        items = MenuItem.query.filter(MenuItem.id.in_(selected_items)).all()
        item_names = [item.name for item in items]  # Extract item names for email
    except SQLAlchemyError as e:
        logger.error(f"Database error when querying menu items: {e}")
        flash("An error occurred while processing your request.", "error")
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

            # Generate Email
            try:
                # Retrieve the latest order for the current user
                latest_order = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).first()

                if not latest_order:
                    flash('No recent order found.', 'error')
                    return redirect(url_for('member_order_bp.menu'))

                # Retrieve the details from the order
                address = latest_order.address
                postal_code = latest_order.postal_code
                phone_number = latest_order.phone_number
            except SQLAlchemyError as e:
                logger.error(f"Database error when retrieving the latest order: {e}")
                flash('An error occurred while processing your request.', 'danger')
                return redirect(url_for('member_order_bp.menu'))

            email_body = render_template("emails/order_email.html",
                                         username=current_user.username,
                                         item=", ".join(item_names),
                                         address=address,
                                         postal_code=postal_code,
                                         phone_number=phone_number,
                                         delivery_date=delivery_date,
                                         delivery_time=delivery_time)

            if send_email(current_user.email, "Order Receipt", html_body=email_body):
                flash("A receipt has been sent to your email address.", 'info')
                logger.info(f"Receipt sent to {current_user.email}")

            logger.info(f"Order {new_order.id} created successfully for customer {new_order.customer_name}.")
            print(f"Order {new_order.id} created successfully for customer {new_order.customer_name}.")
            clear_session_data(['selected_items', 'delivery_date', 'delivery_time'])
            return redirect(url_for('member_order_bp.success'))

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error when creating order: {e}")
            flash("An error occurred while creating your order.", "danger")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            flash("An unexpected error occurred.", "danger")

        return redirect(url_for('member_order_bp.success'))

    elif request.method == "POST":
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in the {getattr(form, field).label.text} field - {error}", 'error')
        logger.warning(f"Order form validation failed: {form.errors}")
        flash('Please fill in all the required fields and captcha.', 'error')

    return render_template('member/order/orders.html', form=form, menu_items=items)


@member_order_bp.route('/order_confirm', methods=['POST', 'GET'])
@login_required
def success():
    check = check_premium_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check
    clear_session_data(['selected_items', 'delivery_date', 'delivery_time'])
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('general_bp.home'))
    return render_template('member/order/success.html')


@member_order_bp.route('/cancel_order/<int:order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):
    check = check_premium_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    csrf_token = request.form.get('csrf_token')
    logger.info(f"Received CSRF token: {csrf_token}")

    try:
        order = Order.query.get(order_id)
        if order and order.user_id == current_user.id:
            if order.status == 'Delivered':
                flash('This order has already been delivered and cannot be cancelled.', 'error')
            elif order.status in ['Order Placed']:
                order.status = 'Cancelled'
                db.session.commit()
                email_body = render_template("emails/cancel_order_email.html",
                                             username=current_user.username,
                                             address=order.address,
                                             postal_code=order.postal_code,
                                             phone_number=order.phone_number,
                                             delivery_date=order.delivery_date,
                                             delivery_time=order.delivery_time)
                if send_email(current_user.email, "Order Cancellation", html_body=email_body):
                    flash('Your order has been successfully cancelled.', 'success')
                    logger.info(f"Receipt sent to {current_user.email}")


            else:
                flash('Order cannot be cancelled.', 'error')
        else:
            flash('Order not found.', 'error')
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error cancelling order {order_id}: {e}")
        flash('An error occurred while trying to cancel your order. Please try again.', 'danger')

    return redirect(url_for('member_order_bp.order_history'))


# Order History Blueprint
@member_order_bp.route('/order_history', methods=['GET'])
@login_required
def order_history():
    check = check_premium_member(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

    # Fetch orders for the current user
    user_id = current_user.id  # Assuming the user is logged in and `current_user` is set
    orders = Order.query.filter_by(user_id=user_id).all()

    # Fetch menu item details for each order
    for order in orders:
        update_order_status(order)
        item_ids = order.selected_items
        order.items_details = MenuItem.query.filter(MenuItem.id.in_(item_ids)).all()
        order.formatted_created_at = pendulum.instance(order.created_at).format("D MMMM YYYY, h:mm A")

    return render_template('member/order/order_history.html', orders=orders)


# Admin viewing of order history
@member_order_bp.route('/admin/members/view/order_history/<int:user_id>', methods=['GET'])
@login_required
def admin_order_history(user_id):
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check

        # Fetch orders for the specified user
    orders = Order.query.filter_by(user_id=user_id).all()

    # Fetch menu item details for each order
    for order in orders:
        update_order_status(order)
        item_ids = order.selected_items
        order.items_details = MenuItem.query.filter(MenuItem.id.in_(item_ids)).all()
        order.formatted_created_at = pendulum.instance(order.created_at).format("D MMMM YYYY, h:mm A")

    return render_template('member/order/admin_order_history.html', orders=orders)