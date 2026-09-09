from pythonforandroid.recipes.sqlite3 import Sqlite3Recipe


assert Sqlite3Recipe._version == "3.50.4"
assert Sqlite3Recipe.depends == []
assert Sqlite3Recipe.python_depends == []


class Sqlite3RecipePinned(Sqlite3Recipe):
    version = "3.50.0"
    # The built-in recipe runs "./configure --disable-tcl && make" on the raw source tree
    # ("canonical" configure mode). The "autoconf" amalgamation tarballs from sqlite.org
    # use the same autosetup script in "autoconf" mode, which does not know --disable-tcl,
    # so keep the same source tree as the built-in recipe.
    url = 'https://github.com/sqlite/sqlite/archive/refs/tags/version-{version}.tar.gz'
    sha512sum = "7ce8f6f34a99a943229fb86f73bda52b6375f727f0a3d9a643fc34c77031f468986ca5153b55a7f36d06567c1e64dbef165f889ebf137570aa4b5755d85a533e"


recipe = Sqlite3RecipePinned()
