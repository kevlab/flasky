from flask import Blueprint

main = Blueprint('main', __name__)

from . import views, errors

# Like applications, blueprints can be defined all in a single file or can be created in a more
# structured way with multiple modules inside a package. To allow for the greatest flexi‐
# bility, a subpackage inside the application package will be created to host the blueprint.
