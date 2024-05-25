from flask import Flask
import flask_sqlalchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:password123@localhost/recipes_db'
app.config['SQLALCHEMY_BINDS'] = {
    'recipes_db': 'mysql://root:password123@localhost/recipes_db'
}
db = flask_sqlalchemy.SQLAlchemy()

from app.admin_recipe_bp import admin_recipe_bp
app.register_blueprint(admin_recipe_bp)
# To put your import statements here
# To put your register blueprint statement here


db.init_app(app)

if __name__ == '__main__':
    app.run(debug=True)

