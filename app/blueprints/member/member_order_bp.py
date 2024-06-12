import logging

from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import MenuItem, Order, OrderItem
from app import db


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('flask_app')

# Create blueprint
member_order_bp = Blueprint('member_order_bp', __name__)


@member_order_bp.route('/home', methods=['POST', 'GET'])
def home():
    return render_template('member/transaction-processing/index.html')


@member_order_bp.route('/menu')
def menu():
    items = MenuItem.query.all()
    return render_template('member/order/menu.html', items=items)


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
