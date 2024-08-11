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
import praw, prawcore
import logging
import sqlite3
import os
from bleach import clean

from app import db
from app.models import Token, Post

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


scopes = ['read', 'identity', 'submit']


def store_refresh_token(token, current_user):
    try:
         # Store the refresh token with the associated user ID
        new_token = Token(user_id=current_user.id, refresh_token=token)
        db.session.add(new_token)
        db.session.commit()
        logging.debug(f"Stored token for user_id {current_user.id}: {token}")
    except Exception as e:
        logging.error(f"Error storing refresh token: {e}")
        db.session.rollback()
        raise


def get_refresh_token(current_user):
    # Retrieve the latest refresh token for the user
    token = Token.query.filter_by(user_id=current_user).order_by(Token.id.desc()).first()
    return token.refresh_token if token else None


@member_forum_bp.route('/authorize')
@login_required
def authorize():
    state = os.urandom(16).hex()
    session['oauth_state'] = state
    auth_url = reddit.auth.url(scopes, state, 'permanent')
    logging.debug(f"Authorization URL: {auth_url}")
    print(auth_url)
    return redirect(auth_url)


@member_forum_bp.route('/authorize_callback')
@login_required
def authorize_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    stored_state = session.get('oauth_state')

    if not code or state != stored_state:
        return "Error: No code returned", 400
    logging.debug(f"Authorization code: {code}")

    try:
        # Get the refresh token
        refresh_token = reddit.auth.authorize(code)
        logging.debug(f"Refresh Token: {refresh_token}")

        # Clear old tokens and store new token
        Token.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        store_refresh_token(refresh_token, current_user)

        return redirect(url_for('member_forum_bp.subreddit'))
    
    except prawcore.exceptions.OAuthException as e:
        logging.error(f"OAuth error: {e}")
        return f"OAuth error: {e}", 400
    except praw.exceptions.PRAWException as e:
        logging.error(f"PRAWException: {e}")
        return f"PRAWException: {e}", 500
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
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


@member_forum_bp.route('/forum')
@login_required
def subreddit():
    user_id = current_user.id
    reddit_user = get_reddit_instance(user_id)
    if not reddit_user:
        return redirect(url_for('member_forum_bp.authorize'))

    try:
        subreddit = reddit_user.subreddit('tastefullyfood')
        posts = [post for post in subreddit.hot(limit=5)]
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
    user_id = current_user.id
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

            
            return redirect(url_for('member_forum_bp.subreddit'))
        except Exception as e:
            logging.error(f"Error creating post: {e}")
            flash(f"Error creating post: {e}", 'danger')

    return render_template("member/forum/create_post.html", form=forum)


@member_forum_bp.route('/forum/post/<string:post_id>', methods=['GET', 'POST'])
@login_required
def post_details(post_id):
    reddit_user = get_reddit_instance(current_user.id)
    if not reddit_user:
        return redirect(url_for('member_forum_bp.authorize'))
    
    try:
        # Fetch the post from Reddit
        submission = reddit_user.submission(id=post_id)
        post = {
            'title': submission.title,
            'body': submission.selftext
        }
        comments = submission.comments.list()  # Fetch all comments for the post
    
        form = PostComment()
        if request.method == 'POST' and form.validate_on_submit():
            comment = clean(form.comment.data)
            # Add a new comment to Reddit
            submission.reply(comment)
            flash('Your comment has been added!', 'success')
            return redirect(url_for('member_forum_bp.post_details', post_id=post_id))
        return render_template('member/forum/post_details.html', post=post, comments=comments, form=form)
    except praw.exceptions.PRAWException as e:
        print("ran")
        logging.error(f"PRAWException: {e}")
        return f"Error fetching post information: {e}", 500
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"Error fetching post information: {e}", 500