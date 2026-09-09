from pythonforandroid.recipes.sqlite3 import Sqlite3Recipe


assert Sqlite3Recipe._version == "3.50.4"
assert Sqlite3Recipe.depends == []
assert Sqlite3Recipe.python_depends == []


class Sqlite3RecipePinned(Sqlite3Recipe):
    version = "3.50.0"
    # The built-in recipe runs "./configure && make" and defaults to the raw source tree
    # from github. The "autoconf" tarball from sqlite.org is the amalgamation plus that
    # same (autosetup) configure script, so it builds the same way.
    url = 'https://www.sqlite.org/2025/sqlite-autoconf-3500000.tar.gz'
    sha512sum = "e72f58e96bf7e37e40beaf5c3bdc0c9746aea454d08422ba49a0afba9bedf0a5f85f7fb17c24b1ef2ddf916e97de3bce77e6ddf7e614f5470636317578440467"


recipe = Sqlite3RecipePinned()
