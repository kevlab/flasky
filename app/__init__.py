from flask import Flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.mail import Mail
from flask.ext.moment import Moment
from flask.ext.sqlalchemy import SQLAlchemy
from config import config

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app

# The way the application is created in the single-file version is very convenient, but it has
# one big drawback. Because the application is created in the global scope, there is no way
# to apply configuration changes dynamically: by the time the script is running, the ap‐
# plication instance has already been created, so it is already too late to make configuration
# changes. This is particularly important for unit tests because sometimes it is necessary
# to run the application under different configuration settings for better test coverage.
# This is why we use a factory function