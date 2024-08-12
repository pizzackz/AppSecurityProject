from flask import (
    Flask,
    current_app,
    Blueprint,
    render_template,
    request,
    redirect,
    session,
    flash,
    url_for,
    jsonify
)
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from app import limiter
import logging
import sqlite3
import os
import random
from sqlalchemy import or_


from app import db
from app.models import Log_account, Log_general, Log_transaction
from app.utils import get_performance_data, check_admin


admin_log_bp = Blueprint("admin_log_bp", __name__, url_prefix='/admin/log')


@admin_log_bp.route('/main_log')    
@login_required
def display_logs():
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check
    general_filter = request.args.get('general_filter', '')
    account_filter = request.args.get('account_filter', '')
    transaction_filter = request.args.get('transaction_filter', '')

    if general_filter:
        log_general_entries = Log_general.query.filter(
            or_(
                Log_general.id.like(f'%{general_filter}%'),
                Log_general.log_datetime.like(f'%{general_filter}%'),
                Log_general.priority_level.like(f'%{general_filter}%'),
                Log_general.user_id.like(f'%{general_filter}%'),
                Log_general.file_subdir.like(f'%{general_filter}%'),
                Log_general.log_info.like(f'%{general_filter}%')
            )
        ).all()
    else:
        log_general_entries = Log_general.query.all()

    if account_filter:
        log_account_entries = Log_account.query.filter(
            or_(
                Log_account.id.like(f'%{account_filter}%'),
                Log_account.log_datetime.like(f'%{account_filter}%'),
                Log_account.priority_level.like(f'%{account_filter}%'),
                Log_account.user_id.like(f'%{account_filter}%'),
                Log_account.file_subdir.like(f'%{account_filter}%'),
                Log_account.log_info.like(f'%{account_filter}%')
            )
        ).all()
    else:
        log_account_entries = Log_account.query.all()

    if transaction_filter:
        log_transaction_entries = Log_transaction.query.filter(
            or_(
                Log_transaction.id.like(f'%{transaction_filter}%'),
                Log_transaction.log_datetime.like(f'%{transaction_filter}%'),
                Log_transaction.priority_level.like(f'%{transaction_filter}%'),
                Log_transaction.user_id.like(f'%{transaction_filter}%'),
                Log_transaction.file_subdir.like(f'%{transaction_filter}%'),
                Log_transaction.log_info.like(f'%{transaction_filter}%')
            )
        ).all()
    else:
        log_transaction_entries = Log_transaction.query.all()

    return render_template('admin/logging/main_log.html',
                           log_general_entries=log_general_entries,
                           log_account_entries=log_account_entries,
                           log_transaction_entries=log_transaction_entries)


@admin_log_bp.route('/dashboard')
@login_required
def dashboard():
    check = check_admin(fallback_endpoint='login_auth_bp.login')
    if check:
        return check
    return render_template('admin/logging/dashboard.html')

@admin_log_bp.route('/api/dashboard1')
@limiter.limit("100 per 1 minutes")
def performance1():

    log_general = Log_general.query.all()
    log_account = Log_account.query.all()
    log_transaction = Log_transaction.query.all()
    now = datetime.utcnow()

    action_count_last_24_hours = []

    # Loop through the last 24 hours
    for i in range(12, 0, -1):
        start_time = now - timedelta(hours=i)
        end_time = now - timedelta(hours=i - 2)
        count = sum(1 for log in log_general if start_time <= log.log_datetime < end_time) + sum(1 for log in log_account if start_time <= log.log_datetime < end_time) + sum(1 for log in log_transaction if start_time <= log.log_datetime < end_time)
        action_count_last_24_hours.append(count)

    return jsonify({'content':action_count_last_24_hours})



@admin_log_bp.route('/api/dashboard2')
@limiter.limit("100 per 1 minutes")
def performance2():

    log_general = Log_general.query.all()
    log_account = Log_account.query.all()
    log_transaction = Log_transaction.query.all()
    now = datetime.utcnow()

    action_count_last_24_hours = []

    # Loop through the last 24 hours
    for i in range(12, 0, -1):
        start_time = now - timedelta(hours=i)
        end_time = now - timedelta(hours=i - 2)
        count = sum(
            1 for log in log_general 
            if start_time <= log.log_datetime < end_time and log.priority_level == 'Error'
        ) + sum(
            1 for log in log_account 
            if start_time <= log.log_datetime < end_time and log.priority_level == 'Error'
        ) + sum(
            1 for log in log_transaction 
            if start_time <= log.log_datetime < end_time and log.priority_level == 'Error'
        )
        action_count_last_24_hours.append(count)

    return jsonify({'content': action_count_last_24_hours})


@admin_log_bp.route('/api/dashboard3')
@limiter.limit("100 per 1 minutes")
def performance3():

    log_general = Log_general.query.all()
    log_account = Log_account.query.all()
    log_transaction = Log_transaction.query.all()
    now = datetime.utcnow()

    action_count_last_24_hours = []

    # Loop through the last 24 hours
    for i in range(12, 0, -1):
        start_time = now - timedelta(hours=i)
        end_time = now - timedelta(hours=i - 2)
        count = sum(
            1 for log in log_general 
            if start_time <= log.log_datetime < end_time and log.priority_level == 'Critical'
        ) + sum(
            1 for log in log_account 
            if start_time <= log.log_datetime < end_time and log.priority_level == 'Critical'
        ) + sum(
            1 for log in log_transaction 
            if start_time <= log.log_datetime < end_time and log.priority_level == 'Critical'
        )
        action_count_last_24_hours.append(count)

    return jsonify({'content': action_count_last_24_hours})



@admin_log_bp.route('/api/dashboard4')
@limiter.limit("100 per 1 minutes")
def performance4():

    log_general = Log_general.query.all()
    log_account = Log_account.query.all()
    log_transaction = Log_transaction.query.all()
    now = datetime.utcnow()

    action_count_last_24_hours = []

    # Loop through the last 24 hours
    for i in range(12, 0, -1):
        start_time = now - timedelta(hours=i)
        end_time = now - timedelta(hours=i - 2)
        count = sum(
            1 for log in log_account 
            if start_time <= log.log_datetime < end_time and log.priority_level == 'Error'
        )
        action_count_last_24_hours.append(count)

    return jsonify({'content': action_count_last_24_hours})