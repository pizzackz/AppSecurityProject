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
from datetime import datetime
import logging
import sqlite3
import os


from app import db
from app.models import Log_account, Log_general, Log_transaction


admin_log_bp = Blueprint("admin_log_bp", __name__, url_prefix='/admin/log')


@admin_log_bp.route('/dashboard')
@login_required
def display_logs():
    log_general_entries = Log_general.query.all()
    log_account_entries = Log_account.query.all()
    log_transaction_entries = Log_transaction.query.all()
    
    return render_template('admin/logging/main_log.html', 
                           log_general_entries=log_general_entries,
                           log_account_entries=log_account_entries,
                           log_transaction_entries=log_transaction_entries)

