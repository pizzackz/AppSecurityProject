import logging
import os
import stripe

from dotenv import load_dotenv
from flask import Blueprint, request, redirect, url_for, render_template, jsonify, flash
from app import db, csrf
from sqlalchemy.sql import func
from app.models import Payment, Member
from app.utils import send_email, log_trans
from datetime import datetime, timedelta,timezone

from flask_login import login_required, current_user

# Set up logging
logger = logging.getLogger('tastefully')

# Create blueprint
member_subscription_bp = Blueprint('member_subscription_bp', __name__)

# Load environment variables from a ..env file
load_dotenv('..env')
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
publishable_key = os.getenv('STRIPE_PUBLISHABLE_KEY')
endpoint_secret = os.getenv('STRIPE_ENDPOINT_SECRET')


if not stripe.api_key:
    raise ValueError("No Stripe API key provided")


@member_subscription_bp.after_request
def add_no_cache_headers(response):
    response.cache_control.no_store = True
    response.cache_control.no_cache = True
    response.cache_control.must_revalidate = True
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


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
        log_trans("Error","transaction", current_user.id, f"Stripe error: {e.user_message}")
        return render_template('error/error_403.html'), 403
    except Exception as e:
        log_trans("Error", "transaction", current_user.id, f"Error: str{e}")
        return render_template('error/error_403.html'), 403


@member_subscription_bp.route('/success', methods=['POST', 'GET'])
@login_required
def success():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('general_bp.home'))

    user_id = request.args.get('user_id')
    action = request.args.get('action')
    stripe_session_id = request.args.get('session_id')  # Get session_id passed in the success URL

    if not stripe_session_id:
        log_trans("Error", "transaction", current_user.id, f"Missing Stripe session ID")
        flash("An error occurred while processing your request. Please try again.", "error")
        return redirect(url_for('member_subscription_bp.plan_select', action='upgrade'))

    try:
        # Retrieve the Stripe session details
        stripe_session = stripe.checkout.Session.retrieve(stripe_session_id)

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
            log_trans("Error", "transaction", current_user.id, f"No user found with ID {user_id}")
            return render_template('error/error_404.html'), 404

        # Ensure that the payment_intent exists in the stripe_session
        subscription_id = stripe_session.subscription
        if not subscription_id:
            log_trans("Error", "transaction", current_user.id, "Subscription ID is missing in the Stripe session")
            return render_template('error/error_400.html'), 400

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

            # Send email receipt
            email_body = render_template("emails/sub_email.html", username=current_user.username)

            if send_email(current_user.email, "Subscription Receipt", html_body=email_body):
                flash("A receipt has been sent to your email address.", 'info')
                log_trans("Info", "transaction", current_user.id, f"Subscription Receipt sent to {current_user.email}")

        else:
            log_trans("Error", "transaction", current_user.id, "No invoice found for the subscription")
            return render_template('error/error_404.html'), 404

    except stripe.error.InvalidRequestError as e:
        log_trans("Error", "transaction", current_user.id, f"Invalid Stripe session ID: {stripe_session_id}")
        return render_template('error/error_400.html'), 400
    except Exception as e:
        db.session.rollback()  # Rollback the session to avoid any partial insertions
        if "Duplicate entry" in str(e):
            log_trans("Error", "transaction", current_user.id, f"Duplicate entry")
            return render_template('error/error_400.html'), 400
        log_trans("Error", "transaction", current_user.id, f"Error retrieving Stripe session")
        return render_template('error/error_500.html'), 500
    except:
        log_trans("Error", "transaction", current_user.id, f"Invalid Stripe session ID: {stripe_session_id}")
        flash("An error occurred while processing your request. Please try again.", "error")
        return redirect(url_for('member_subscription_bp.plan_select', action='upgrade'))

    return render_template('member/transaction-processing/success.html')



@member_subscription_bp.route('/cancel', methods=['POST', 'GET'])
@login_required
def cancel():
    if request.method == "POST":
        if request.form.get('return') == 'True':
            return redirect(url_for('general_bp.home'))
    return render_template('member/transaction-processing/cancel.html')


