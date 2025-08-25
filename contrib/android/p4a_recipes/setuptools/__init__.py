from pythonforandroid.recipes.setuptools import SetuptoolsRecipe


assert SetuptoolsRecipe._version == "69.2.0"
assert SetuptoolsRecipe.depends == ['python3']
assert SetuptoolsRecipe.python_depends == []


class SetuptoolsRecipePinned(SetuptoolsRecipe):
    sha512sum = "e69abe573304b1c2c074144c9df663fec0d6ce617359f070ca8d57710e4beb99435d0d2124d45a7d8b24889693597e1e03875bc6ff960fa31f6250e1c253b906"


recipe = SetuptoolsRecipePinned()
