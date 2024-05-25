from flask import Flask, current_app, Blueprint, render_template, request, redirect, session, flash, url_for
from app import db

test_blueprint = Blueprint("test_blueprint", __name__)



@test_blueprint.route('/test', methods=['GET', 'POST'])
def test():
    return 'works'