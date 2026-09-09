from pythonforandroid.recipe import PythonRecipe
from pythonforandroid.util import HashPinnedDependency


assert PythonRecipe.depends == ['python3']
assert PythonRecipe.python_depends == []


class PlyerRecipePinned(PythonRecipe):
    version = "5262087c85b2c82c69e702fe944069f1d8465fdf"
    url = "git+https://github.com/SomberNight/plyer"
    depends = ["setuptools"]
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
    ]


recipe = PlyerRecipePinned()
