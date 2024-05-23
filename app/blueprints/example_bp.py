from flask import Blueprint, render_template  # Need to first import 'Blueprint' from Flask

# This is just an example showing how to use blueprints
# Please try to only have 1 blueprint each .py file and that the name of blueprint should postfix '_bp'

# Creating blueprints
# 1st parameter -- name: Name of blueprint, 2nd parameter just put '__name__'
example_bp: Blueprint = Blueprint("example_bp", __name__)


# Defining routes under a blueprint
# Need to write '@<blueprint_var_name>.route'
@example_bp.route("/example")
def example_route():
    # Do not return pure html tags, this is just for an example
    return "<h1>This is an example route created under example_bp blueprint</h1>"


# We're going to create a test route here to look at how to use url_for() in Jinja to link to blueprint routes
@example_bp.route("/example_bp_test")
def test_route():
    return render_template("example_bp_template.html")
