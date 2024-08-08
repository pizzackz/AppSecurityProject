from flask import (
    current_app,
    Blueprint,
    render_template,
    request,
    redirect,
    flash,
    url_for,
    jsonify
)
from flask_login import login_required, current_user
from app import db
import requests
from ..models import User

home_bp = Blueprint('home_bp', __name__)

@home_bp.route('/')
def home():
    user = current_user
    try:
        account_type = user.type
        if account_type == 'member':
            return render_template('member/home.html')
        elif account_type == 'admin':
            return render_template('admin/home.html')
    except AttributeError:
        return redirect(url_for('login_auth_bp.login'))