from flask import Flask
from blueprints.admin_recipe_bp import admin_recipe_bp
import os

app = Flask(__name__)

app.register_blueprint(admin_recipe_bp)

if __name__ == '__main__':
    app.run(debug=True)