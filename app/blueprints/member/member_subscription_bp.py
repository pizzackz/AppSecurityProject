# /blueprints/member/member_subscription_bp.py
import logging
import os
from dotenv import load_dotenv

import stripe
from flask import Blueprint, session, request, redirect, url_for, render_template, jsonify

load_dotenv('.env')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('flask_app')

# Log the loaded keys
# logger.info(f"Loaded Stripe Secret Key: {os.getenv('STRIPE_SECRET_KEY')}")
# logger.info(f"Loaded Stripe Publishable Key: {os.getenv('STRIPE_PUBLISHABLE_KEY')}")

# Create blueprint
member_subscription_bp = Blueprint('member_subscription_bp', __name__)

# Load environment variables from a .env file
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
publishable_key = os.getenv('STRIPE_PUBLISHABLE_KEY')

if not stripe.api_key:
    raise ValueError("No Stripe API key provided")


# Placeholder for member index/home page, can be replaced
@member_subscription_bp.route('/home', methods=['POST', 'GET'])
def home():
    return render_template('member/transaction-processing/index.html')


@member_subscription_bp.route('/plan_select', methods=['POST', 'GET'])
def plan_select():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('member_subscription_bp.home'))
        return redirect(url_for("member_subscription_bp.checkout"))
    return render_template('member/transaction-processing/plan_select.html')


@member_subscription_bp.route('/checkout', methods=['POST', 'GET'])
def checkout():
    return render_template('member/transaction-processing/checkout.html', publishable_key=publishable_key)


@member_subscription_bp.route('/create-checkout-session', methods=['POST', 'GET'])
def create_checkout_session():
    try:
        # Use the price ID from the Stripe Dashboard
        price_id = "price_1PKI5Y06BsEMbNMkj9KPsZTX"

        stripe_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('member_subscription_bp.success', _external=True),
            cancel_url=url_for('member_subscription_bp.cancel', _external=True),
        )
        return jsonify({'id': stripe_session.id})
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e.user_message}")
        return jsonify(error=e.user_message), 403
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify(error=str(e)), 403


@member_subscription_bp.route('/success')
def success():
    return render_template('/member/transaction-processing/success.html')


@member_subscription_bp.route('/cancel')
def cancel():
    return render_template('/member/transaction-processing/cancel.html')


@member_subscription_bp.route('/plan_confirm')
def plan_confirm():
    return render_template('/member/transaction-processing/plan_confirm.html')
