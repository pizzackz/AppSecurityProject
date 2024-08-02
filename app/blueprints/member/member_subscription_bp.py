import logging
import os
import stripe

from dotenv import load_dotenv
from flask import Blueprint, request, redirect, url_for, render_template, jsonify, session
from app import db, csrf
from sqlalchemy.sql import func
from app.models import Payment, Member
from datetime import datetime, timedelta,timezone

from flask_login import login_required, current_user

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
@login_required
def plan_select():
    action = request.args.get('action', None)
    return render_template('member/transaction-processing/plan_select.html', action=action)


@member_subscription_bp.route('/create-checkout-session', methods=['GET', 'POST'])
@login_required
def create_checkout_session():
    action = request.args.get('action', None)  # Capture the action
    user_id = current_user.id
    try:
        price_id = "price_1PKI5Y06BsEMbNMkj9KPsZTX"  # Price ID for the subscription plan
        stripe_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('member_subscription_bp.success', _external=True) +
                        f"?user_id={user_id}&action={action}&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=url_for('member_subscription_bp.cancel', _external=True),
            metadata={
                'user_id': str(user_id),
                'action': action
            }
        )

        return redirect(stripe_session.url, code=303)
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e.user_message}")
        return jsonify(error=e.user_message), 403
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify(error=str(e)), 403


@member_subscription_bp.route('/success', methods=['POST', 'GET'])
@login_required
def success():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('home_bp.home'))

    user_id = request.args.get('user_id')
    action = request.args.get('action')
    stripe_session_id = request.args.get('session_id')  # Get session_id passed in the success URL

    if not stripe_session_id:
        logger.error("Missing Stripe session ID")
        return jsonify({'error': 'Missing Stripe session ID'}), 400

    try:
        # Retrieve the Stripe session details
        stripe_session = stripe.checkout.Session.retrieve(stripe_session_id)
        logger.info(f"Retrieved Stripe session: {stripe_session}")

        user = Member.query.get(user_id)
        if user:
            # Database updates
            if user.subscription_end_date is not None:
                if user.subscription_end_date.tzinfo is None:
                    user.subscription_end_date = user.subscription_end_date.replace(tzinfo=timezone.utc)
            else:
                user.subscription_end_date = datetime.now(timezone.utc)  # Set a default value if None

            if user.subscription_plan == "premium":
                action = 'renew'  # Override action to 'renew' if already premium

                # Handle subscription actions
                if action in ['upgrade', 'renew']:
                    user.subscription_plan = "premium"
                    if user.subscription_end_date and user.subscription_end_date > datetime.now(timezone.utc):
                        user.subscription_end_date += timedelta(days=30)
                    else:
                        user.subscription_end_date = datetime.now(timezone.utc) + timedelta(days=30)
            else:
                user.subscription_plan = "premium"
                user.subscription_end_date = datetime.now(timezone.utc) + timedelta(days=30)


            db.session.commit()
        else:
            logger.error(f"No user found with ID {user_id}")
            return jsonify({'error': 'User not found'}), 404

        # Ensure that the payment_intent exists in the stripe_session
        subscription_id = stripe_session.subscription
        if not subscription_id:
            logger.error("Subscription ID is missing in the Stripe session")
            return jsonify({'error': 'Subscription ID is missing in the Stripe session'}), 400

        subscription = stripe.Subscription.retrieve(subscription_id)
        latest_invoice_id = subscription.latest_invoice

        if latest_invoice_id:
            invoice = stripe.Invoice.retrieve(latest_invoice_id)

            new_payment = Payment(
                user_id=user.id,
                stripe_payment_id=invoice.id,  # Assuming your Payment model has this field
                amount=invoice.amount_paid,
                currency=invoice.currency,
                status=invoice.status,
                created_at=datetime.fromtimestamp(invoice.created, timezone.utc)
            )

            db.session.add(new_payment)
            db.session.commit()

        else:
            logger.error("No invoice found for the subscription")
            return jsonify({'error': 'No invoice found for the subscription'}), 404

    except stripe.error.InvalidRequestError as e:
        logger.error(f"Invalid Stripe session ID: {stripe_session_id}")
        return jsonify({'error': f'Invalid Stripe session ID: {e.user_message}'}), 400
    except Exception as e:
        logger.error(f"Error retrieving Stripe session: {e}")
        return jsonify({'error': f'Error retrieving Stripe session: {str(e)}'}), 500

    return render_template('member/transaction-processing/success.html')



@member_subscription_bp.route('/cancel', methods=['POST', 'GET'])
@login_required
def cancel():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('home'))
    return render_template('member/transaction-processing/cancel.html')


