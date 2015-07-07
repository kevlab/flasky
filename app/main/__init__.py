from flask import Blueprint

main = Blueprint('main', __name__)

from . import views, errors

# Like applications, blueprints can be defined all in a single file or can be created in a more
# structured way with multiple modules inside a package. To allow for the greatest flexi‐
# bility, a subpackage inside the application package will be created to host the blueprint.

from ..models import Permission

@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)

# Permissions may also need to be checked from templates, so the Permission class with
# all the bit constants needs to be accessible to them. To avoid having to add a template
# argument in every render_template() call, a context processor is used.
