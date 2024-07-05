import logging

from logging import Logger
from flask import Blueprint, request, session, redirect, render_template, flash
from werkzeug.security import check_password_hash
from typing import Optional, Dict, List