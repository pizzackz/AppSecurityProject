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
import praw
import logging
import sqlite3
import os

from app import db
from app.models import Token, Post

from app.forms.forms import ForumPost

member_forum_bp = Blueprint("member_forum_bp", __name__)

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

# Assuming 'read' and 'identity' scopes are needed for your task
scopes = ['read', 'identity']

def store_refresh_token(token):
    new_token = Token(refresh_token=token)
    db.session.add(new_token)
    db.session.commit()

def get_refresh_token():
    token = Token.query.order_by(Token.id.desc()).first()
    return token.refresh_token if token else None


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
        return redirect(url_for('general_bp.home'))
    except Exception as e:
        logging.error(f"Error during authorization: {e}")
        return f"Error during authorization: {e}", 500


def get_reddit_instance():
    """Create a Reddit instance using the stored refresh token."""
    refresh_token = get_refresh_token()
    if refresh_token:
        return praw.Reddit(
            client_id=REDDIT_CLIENT_ID,
            client_secret=REDDIT_CLIENT_SECRET,
            user_agent=REDDIT_USER_AGENT,
            refresh_token=refresh_token
        )
    else:
        return None


@member_forum_bp.route('/forum')
def subreddit():
    reddit_user = get_reddit_instance()
    if not reddit_user:
        return redirect(url_for('authorize'))

    try:
        subreddit = reddit_user.subreddit('food')
        posts = [post.title for post in subreddit.hot(limit=5)]
        return render_template('member/forum/customer_forum.html', posts=posts)
    except praw.exceptions.PRAWException as e:
        logging.error(f"PRAWException: {e}")
        return f"Error fetching subreddit information: {e}", 500
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"Error fetching subreddit information: {e}", 500


@member_forum_bp.route('/forum/create_post', methods=["GET", "POST"])
def create_post():
    reddit_user = get_reddit_instance()
    if not reddit_user:
        return redirect(url_for('authorize'))

    forum = ForumPost
    if request.method == 'POST' and forum.validate_on_submit():
        title = forum.title.data
        body = forum.body.data
        try:
            submission = reddit_user.subreddit('food').submit(title, selftext=body)
            
            # Store post information in the database
            new_post = Post(
                reddit_id=submission.id,
                title=submission.title,
                body=submission.body,
                created_at=submission.created_at
            )
            db.session.add(new_post)
            db.session.commit()
            
            return jsonify({'message': 'Post created successfully!', 'post_id': submission.id}), 201
        except Exception as e:
            logging.error(f"Error creating post: {e}")
    return render_template("member/forum/create_post.html", form=forum)
