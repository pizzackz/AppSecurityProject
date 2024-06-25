import logging

from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import MenuItem, Order, OrderItem
from app.forms.forms import OrderForm, MenuForm
from app import db, csrf
from sqlalchemy import text


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('flask_app')

# Create blueprint
member_order_bp = Blueprint('member_order_bp', __name__)

from app.models import MenuItem, db


@member_order_bp.route('/home', methods=['POST', 'GET'])
def home():
    return render_template('recipe/transaction-processing/index.html')


@member_order_bp.route('/menu', methods=['POST', 'GET'])
def menu():
    form = MenuForm()
    items = MenuItem.query.all()

    if request.method == "POST":
        selected_items = request.form.getlist('menu_item_id')
        return redirect(url_for('member_order_bp.order', selected_items=selected_items))

    return render_template('recipe/order/menu.html', menu_items=items, form=form)


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

    return render_template('recipe/order/orders.html', form=form, menu_items=items)



@member_order_bp.route('/order_confirm', methods=['POST', 'GET'])
def success():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('member_subscription_bp.home'))
    return render_template('recipe/order/success.html')

