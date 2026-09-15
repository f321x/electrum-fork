import os

from pythonforandroid.recipes.hostqt6 import HostQt6Recipe
from pythonforandroid.util import load_source

qt6 = load_source('qt6', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'qt6', '__init__.py'))

assert HostQt6Recipe._version == "6.10.2"


class HostQt6RecipePinned(HostQt6Recipe):
    # Build host tools from the same pinned sources as the Android Qt libraries.
    version = qt6.recipe.version
    url = qt6.recipe.url
    sha256sum = qt6.recipe.sha256sum


recipe = HostQt6RecipePinned()
