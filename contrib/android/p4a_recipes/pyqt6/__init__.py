import os

from pythonforandroid.recipes.pyqt6 import PyQt6Recipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PyQt6Recipe._version == "6.10.2"
assert PyQt6Recipe.depends == ['qt6', 'pyjnius', 'setuptools', 'pyqt6sip', 'hostpython3', 'pyqt_builder', 'python3'], PyQt6Recipe.depends
assert PyQt6Recipe.python_depends == []


class PyQt6RecipePinned(util.InheritedRecipeMixin, PyQt6Recipe):
    version = "6.11.0"
    sha512sum = "41f5f1f33eb2120d4966775455c63cdfeb8375dd268d330f163b6a76928a958b9cf53a6bad3050d819b9deadaa2118f194a84c19e518c9d75db34a146aa52366"


recipe = PyQt6RecipePinned()
