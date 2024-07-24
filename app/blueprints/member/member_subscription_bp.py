import logging
import os
import stripe

from dotenv import load_dotenv
from flask import Blueprint, request, redirect, url_for, render_template, jsonify
from app import db, csrf
from sqlalchemy.sql import func
from app.models import Payment

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('flask_app')

# Create blueprint
member_subscription_bp = Blueprint('member_subscription_bp', __name__)

# Load environment variables from a ..env file
load_dotenv('..env')
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
publishable_key = os.getenv('STRIPE_PUBLISHABLE_KEY')
endpoint_secret = os.getenv('STRIPE_ENDPOINT_SECRET')

if not stripe.api_key:
    raise ValueError("No Stripe API key provided")


@member_subscription_bp.route('/home', methods=['POST', 'GET'])
def home():
    return render_template('member/transaction-processing/index.html')


@member_subscription_bp.route('/plan_select', methods=['POST', 'GET'])
def plan_select():
    return render_template('member/transaction-processing/plan_select.html')


@member_subscription_bp.route('/create-checkout-session', methods=['GET', 'POST'])
def create_checkout_session():
    try:
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
        return redirect(stripe_session.url, code=303)
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e.user_message}")
        return jsonify(error=e.user_message), 403
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify(error=str(e)), 403


@member_subscription_bp.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        return jsonify({'error': str(e)}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return jsonify({'error': str(e)}), 400

    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']

        new_payment = Payment(
            stripe_payment_id=payment_intent['id'],
            amount=payment_intent['amount'],
            currency=payment_intent['currency'],
            status=payment_intent['status'],
            created_at=func.now()
        )
        db.session.add(new_payment)
        db.session.commit()

        logger.info(f"Payment stored: {new_payment}")

    return jsonify({'status': 'success'}), 200


@member_subscription_bp.route('/success', methods=['POST', 'GET'])
def success():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('member_subscription_bp.home'))
    return render_template('member/transaction-processing/success.html')


@member_subscription_bp.route('/cancel', methods=['POST', 'GET'])
def cancel():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('member_subscription_bp.home'))
    return render_template('member/transaction-processing/cancel.html')


@member_subscription_bp.route('/plan_confirm')
def plan_confirm():
    return render_template('member/transaction-processing/plan_confirm.html')
