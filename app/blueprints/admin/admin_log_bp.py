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
import logging
import sqlite3
import os
import random


from app import db
from app.models import Log_account, Log_general, Log_transaction
from app.utils import get_performance_data


admin_log_bp = Blueprint("admin_log_bp", __name__, url_prefix='/admin/log')


@admin_log_bp.route('/main_log')    
@login_required
def display_logs():
    log_general_entries = Log_general.query.all()
    log_account_entries = Log_account.query.all()
    log_transaction_entries = Log_transaction.query.all()
    
    return render_template('admin/logging/main_log.html', 
                           log_general_entries=log_general_entries,
                           log_account_entries=log_account_entries,
                           log_transaction_entries=log_transaction_entries)


@admin_log_bp.route('/dashboard')
def dashboard():
    return render_template('admin/logging/dashboard.html')

@admin_log_bp.route('/api/dashboard1')
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
            if start_time <= log.log_datetime < end_time and log.priority_level == 'Info'
        )
        action_count_last_24_hours.append(count)

    return jsonify({'content': action_count_last_24_hours})