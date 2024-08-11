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


def store_refresh_token(token, current_user):
    try:
        new_token = Token(user_id=current_user.id, refresh_token=token)
        db.session.add(new_token)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error storing refresh token: {e}")
        db.session.rollback()
        raise



def get_refresh_token(user_id):
    token = Token.query.filter_by(user_id=user_id).order_by(Token.id.desc()).first()
    return token.refresh_token if token else None


@admin_forum_bp.route('/admin/authorize')
@login_required
def authorize():
    if current_user != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    
    auth_url = reddit.auth.url(scopes, os.urandom(16).hex(), 'permanent')
    logging.debug(f"Authorization URL: {auth_url}")
    print(auth_url)
    return redirect(auth_url)


@admin_forum_bp.route('/admin/authorize_callback')
@login_required
def authorize_callback():
    if current_user != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401

    code = request.args.get('code')
    if not code:
        return "Error: No code returned", 400
    logging.debug(f"Authorization code: {code}")
    try:
        # Get the refresh token
        refresh_token = reddit.auth.authorize(code)
        logging.debug(f"Refresh Token: {refresh_token}")

        # Ensure only one token per user
        Token.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()

        # Store the refresh token securely associated with the current user
        # Assuming you have access to the current user's ID
        store_refresh_token(refresh_token, current_user)
        return redirect(url_for('member_forum_bp.subreddit'))
    except Exception as e:
        logging.error(f"Error during authorization: {e}")
        return f"Error during authorization: {e}", 500


def get_reddit_instance(user_id):
    """Create a Reddit instance using the stored refresh token."""
    refresh_token = get_refresh_token(user_id)
    if refresh_token:
        try:
            return praw.Reddit(
                client_id=REDDIT_CLIENT_ID,
                client_secret=REDDIT_CLIENT_SECRET,
                user_agent=REDDIT_USER_AGENT,
                refresh_token=refresh_token
            )
        except praw.exceptions.InvalidToken as e:
            logging.error(f"Invalid token error: {e}")
            return None
    else:
        return None


scopes = ['read', 'identity', 'submit', 'comment','modposts'] 


@admin_forum_bp.route("/admin/forum")
@login_required
def admin_forum():
    if current_user.type != 'admin':
        # return 401 if user is not admin
        return jsonify({"message": "Unauthorized"}), 401
    
    user_id = current_user.id
    reddit_user = get_reddit_instance(user_id)
    if not reddit_user:
        return redirect(url_for('admin_forum_bp.authorize'))
    
    try:
        subreddit = reddit_user.subreddit('tastefullyfood')
        posts = [post for post in subreddit.hot(limit=None)]
        return render_template('admin/forum/admin_forum.html', posts=posts)
    except praw.exceptions.PRAWException as e:
        logging.error(f"PRAWException: {e}")
        return f"Error fetching subreddit information: {e}", 500
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"Error fetching subreddit information: {e}", 500
    

@admin_forum_bp.route("/admin/delete_post/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 401

    post = Post.query.get(post_id)
    if post:
        try:
            # Delete from Reddit
            reddit_user = get_reddit_instance()
            submission = reddit_user.submission(id=post.reddit_id)
            submission.delete()

            # Delete from local database
            db.session.delete(post)
            db.session.commit()
            return jsonify({"message": "Post deleted successfully"}), 200
        except Exception as e:
            logging.error(f"Error deleting post: {e}")
            return jsonify({"message": f"Error deleting post: {e}"}), 500
    return jsonify({"message": "Post not found"}), 404


@admin_forum_bp.route("/admin/delete_comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    if not current_user.is_admin:
        return jsonify({"message": "Unauthorized"}), 401

    comment = Post_comments.query.get(comment_id)
    if comment:
        try:
            # Delete from Reddit
            reddit_user = get_reddit_instance()
            reddit_comment = reddit_user.comment(id=comment.reddit_comment_id)
            reddit_comment.delete()

            # Delete from local database
            db.session.delete(comment)
            db.session.commit()
            return jsonify({"message": "Comment deleted successfully"}), 200
        except Exception as e:
            logging.error(f"Error deleting comment: {e}")
            return jsonify({"message": f"Error deleting comment: {e}"}), 500
    return jsonify({"message": "Comment not found"}), 404