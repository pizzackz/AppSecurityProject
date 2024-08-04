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
scopes = ['read', 'identity', 'submit'] 


def store_refresh_token(token):
    new_token = Token(user_id=current_user.id, refresh_token=token)
    db.session.add(new_token)
    db.session.commit()


def get_refresh_token(current_user):
    token = Token.query.filter_by(user_id=current_user.id).order_by(Token.id.desc()).first()
    return token.refresh_token if token else None


@member_forum_bp.route('/authorize')
@login_required
def authorize():
    auth_url = reddit.auth.url(scopes, 'random_string', 'permanent')
    logging.debug(f"Authorization URL: {auth_url}")
    return redirect(auth_url)


@member_forum_bp.route('/authorize_callback')
@login_required
def authorize_callback():
    code = request.args.get('code')
    if not code:
        return "Error: No code returned", 400
    logging.debug(f"Authorization code: {code}")
    try:
        # Get the refresh token
        refresh_token = reddit.auth.authorize(code)
        logging.debug(f"Refresh Token: {refresh_token}")

        # Store the refresh token securely associated with the current user
        # Assuming you have access to the current user's ID
        current_user_id = current_user.id  # Implement this function to get the current logged-in user's ID
        store_refresh_token(refresh_token, current_user_id)
    except Exception as e:
        logging.error(f"Error during authorization: {e}")
        return f"Error during authorization: {e}", 500


def get_reddit_instance(current_user):
    """Create a Reddit instance using the stored refresh token."""
    refresh_token = get_refresh_token(current_user)
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
@login_required
def subreddit():
    print(current_user)
    user_id = current_user
    reddit_user = get_reddit_instance(user_id)
    if not reddit_user:
        return redirect(url_for('member_forum_bp.authorize'))

    try:
        subreddit = reddit_user.subreddit('tastefullyfood')
        posts = [post.title for post in subreddit.hot(limit=5)]
        return render_template('member/forum/customer_forum.html', posts=posts)
    except praw.exceptions.PRAWException as e:
        logging.error(f"PRAWException: {e}")
        return f"Error fetching subreddit information: {e}", 500
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"Error fetching subreddit information: {e}", 500


@member_forum_bp.route('/forum/create_post', methods=["GET", "POST"])
@login_required
def create_post():
    user_id = current_user
    reddit_user = get_reddit_instance(user_id)
    if not reddit_user:
        return redirect(url_for('member_forum_bp.authorize'))

    forum = ForumPost()
    if request.method == 'POST' and forum.validate_on_submit():
        title = clean(forum.title.data)
        body = clean(forum.body.data)
        try:
            submission = reddit_user.subreddit('tastefullyfood').submit(title, selftext=body)
            print(f"submission = {submission}")
            # Store post information in the database 
            new_post = Post(
                reddit_id=submission.id,
                title=title,
                body=body,
                created_at=submission.created_at
            )
            db.session.add(new_post)
            db.session.commit()
            
            flash('Post created successfully!', 'success')
            return redirect("url_for('member_forum_bp.subreddit')")
        except Exception as e:
            logging.error(f"Error creating post: {e}")
            flash(f"Error creating post: {e}", 'danger')
    return render_template("member/forum/create_post.html", form=forum)


@member_forum_bp.route('/forum/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def post_details(post_id):
    user_id = current_user
    reddit_user = get_reddit_instance(user_id)
    if not reddit_user:
        return redirect(url_for('member_forum_bp.authorize'))
    
    post = Post.query.get_or_404(post_id)
    comment = PostComment
    if comment.validate_on_submit():
        new_comment = Post_comments(
            post_id=post.id,
            body=comment.body.data
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('Your comment has been added!', 'success')
        return redirect(url_for('member_forum_bp.post_details', post_id=post.id))
    
    comments = PostComment.query.filter_by(post_id=post.id).order_by(PostComment.created_at).all()
    return render_template('member/forum/post_details.html', post=post, comments=comments, form=comment)
