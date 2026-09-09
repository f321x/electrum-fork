import os

from pythonforandroid.recipes.cffi import CffiRecipe
from pythonforandroid.util import load_source, HashPinnedDependency

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert CffiRecipe._version == "2.0.0"
assert CffiRecipe.depends == ['pycparser', 'libffi', 'python3'], CffiRecipe.depends
assert CffiRecipe.python_depends == []


class CffiRecipePinned(util.InheritedRecipeMixin, CffiRecipe):
    sha512sum = "a71b74e642e11eb50e9bb4ae0e7116bdb3c4a7c9622a3766d84506fa7994c02e09644b41b439b95ca99b0303e91891897cff38018d498eb087e0961f0ad4fb8b"
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
    ]


recipe = CffiRecipePinned()
