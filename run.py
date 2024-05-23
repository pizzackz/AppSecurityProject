from flask import Flask
from app import create_app

# Create Flask application instance
app: Flask = create_app()

# Run Flask app in debug mode
if __name__ == '__main__':
    app.run(debug=True)
