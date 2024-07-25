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
)
import praw
import logging
import sqlite3
import os

from app import db
from app.models import Token

member_forum_bp = Blueprint("member_forum_bp", __name__)

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Replace these with your Reddit app credentials
CLIENT_ID = 'FSHdft2_A9qmpG28_rAFGg'
CLIENT_SECRET = '47fiOak87RXcTguWGTayTXUjyrscUw'
USER_AGENT = 'Python:Tastefully:1.0 (by /u/xdninsans)'

# Initialize PRAW
reddit = praw.Reddit(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    user_agent=USER_AGENT,
    redirect_uri='http://localhost:5000/authorize_callback'
)

# Assuming 'read' and 'identity' scopes are needed for your task
scopes = ['read', 'identity']

def store_refresh_token(token):
    new_token = Token(refresh_token=token)
    db.session.add(new_token)
    db.session.commit()

def get_refresh_token():
    token = Token.query.order_by(Token.id.desc()).first()
    return token.refresh_token if token else None

@member_forum_bp.route('/')
def home():
    return '<a href="/authorize">Authorize with Reddit</a>'


@member_forum_bp.route('/authorize')
def authorize():
    auth_url = reddit.auth.url(scopes, 'random_string', 'permanent')
    logging.debug(f"Authorization URL: {auth_url}")
    return redirect(auth_url)


@member_forum_bp.route('/authorize_callback')
def authorize_callback():
    code = request.args.get('code')
    if not code:
        return "Error: No code returned", 400
    logging.debug(f"Authorization code: {code}")
    try:
        # Get the refresh token
        refresh_token = reddit.auth.authorize(code)
        logging.debug(f"Refresh Token: {refresh_token}")

        # Store the refresh token securely
        store_refresh_token(refresh_token)
        return redirect(url_for('me'))
    except Exception as e:
        logging.error(f"Error during authorization: {e}")
        return f"Error during authorization: {e}", 500


def get_reddit_instance():
    """Create a Reddit instance using the stored refresh token."""
    refresh_token = get_refresh_token()
    if refresh_token:
        return praw.Reddit(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            user_agent=USER_AGENT,
            refresh_token=refresh_token
        )
    else:
        return None


@member_forum_bp.route('/me')
def me():
    reddit_user = get_reddit_instance()
    if not reddit_user:
        return redirect(url_for('authorize'))

    try:
        user = reddit_user.user.me()
        return f'Hello, {user.name}!'
    except Exception as e:
        logging.error(f"Error fetching user information: {e}")
        return f"Error fetching user information: {e}", 500


@member_forum_bp.route('/subreddit')
def subreddit():
    reddit_user = get_reddit_instance()
    if not reddit_user:
        return redirect(url_for('authorize'))

    try:
        subreddit = reddit_user.subreddit('learnpython')
        posts = [post.title for post in subreddit.hot(limit=5)]
        return render_template('template_test.html', posts=posts)
    except Exception as e:
        logging.error(f"Error fetching subreddit information: {e}")
        return f"Error fetching subreddit information: {e}", 500
