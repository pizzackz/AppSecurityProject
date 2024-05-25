from flask import Flask, Response
# from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

from .config import Config


# Main file to define a function to create a flask application instance
# Used to "combine" all important blueprints & configurations together in order to run flask app
# Initialise CSRF protection, SQLAlchemy & Flask-Login
csrf: CSRFProtect = CSRFProtect()
db: SQLAlchemy = SQLAlchemy()
# login_manager: LoginManager = LoginManager()


def create_app() -> Flask:
    app: Flask = Flask(__name__)  # Create Flask application instance
    app.config.from_object(Config)  # Load configuration from Config class in 'config.py'

    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:password123@localhost/recipes_db'
    app.config['SQLALCHEMY_BINDS'] = {
        'recipes_db': 'mysql://root:password123@localhost/recipes_db'
    }


    # Enable CSRF protection, SQLAlchemy & Flask-Login for app
    csrf.init_app(app)
    # db.init_app(app)
    # login_manager.init_app(app)

    # Set Content Security Policy header to mitigate XSS attacks
    @app.after_request
    def set_security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self';"
            "style-src 'self'"
            "script-src 'self'"
        )
        return response

    # Register blueprints
    # Registering blueprint from blueprints.example_bp.py
    # from .blueprints.example_bp import example_bp
    # app.register_blueprint(example_bp)
    from app.admin_recipe_bp import admin_recipe_bp
    app.register_blueprint(admin_recipe_bp)

    db.init_app(app)

    # Return Flask app instance
    return app

