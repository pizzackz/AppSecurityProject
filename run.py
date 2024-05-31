from flask import Flask
from app import create_app, db
from app.populate_database import populate_database

# Create Flask application instance
app: Flask = create_app()

# Run Flask app in debug mode
if __name__ == "__main__":
    # Populate database with necessary data
    # Comment out after you have populated the database so that you will get duplicate records
    populate_database(app, db)

    # app.run(debug=True)
