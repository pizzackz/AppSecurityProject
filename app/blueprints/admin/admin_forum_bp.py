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
import praw
import logging
import sqlite3
import os
from bleach import clean

from app import db
from app.models import Token, Post, Post_comments

from app.forms.forms import ForumPost, PostComment

admin_forum_bp = Blueprint("admin_forum_bp", __name__)


# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
REDDIT_CLIENT_ID = os.environ.get('REDDIT_CLIENT_ID')
REDDIT_CLIENT_SECRET = os.environ.get('REDDIT_CLIENT_SECRET')
REDDIT_USER_AGENT = os.environ.get('REDDIT_USER_AGENT')


# Initialize PRAW
reddit = praw.Reddit(
    client_id=REDDIT_CLIENT_ID,
    client_secret=REDDIT_CLIENT_SECRET,
    user_agent=REDDIT_USER_AGENT,
    redirect_uri='http://localhost:5000/authorize_callback'
)


scopes = ['read', 'identity', 'submit', 'comment','modposts'] 


@admin_forum_bp.route("/admin/forum")
@login_required
def admin_forum():
     if current_user != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
     
     
