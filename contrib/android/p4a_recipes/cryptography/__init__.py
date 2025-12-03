from os.path import join, realpath, dirname, isfile
from os import environ
import glob
import sh
from unittest import mock

from pythonforandroid.recipe import PythonRecipe, Recipe
from pythonforandroid.logger import info_main, shprint, error, info, warning
from pythonforandroid.util import ensure_dir, current_directory


def patch_wheel_setuptools_logging():
    """
    When setuptools is not present and the root logger has no handlers,
    Wheels would configure the root logger with DEBUG level, refs:
    - https://github.com/pypa/wheel/blob/0.44.0/src/wheel/util.py
    - https://github.com/pypa/wheel/blob/0.44.0/src/wheel/_setuptools_logging.py

    Both of these conditions are met in our CI, leading to very verbose
    and unreadable `sh` logs. Patching it prevents that.
    """
    return mock.patch("wheel._setuptools_logging.configure")


class PyProjectRecipe(PythonRecipe):
    """Recipe for projects which contain `pyproject.toml`"""

    # Extra args to pass to `python -m build ...`
    extra_build_args = []
    call_hostpython_via_targetpython = False

    def get_recipe_env(self, arch, **kwargs):
        # Custom hostpython
        self.ctx.python_recipe.python_exe = join(
            self.ctx.python_recipe.get_build_dir(arch), "android-build", "python3")
        env = super().get_recipe_env(arch, **kwargs)
        build_dir = self.get_build_dir(arch)
        ensure_dir(build_dir)
        build_opts = join(build_dir, "build-opts.cfg")

        with open(build_opts, "w") as file:
            file.write("[bdist_wheel]\nplat_name={}".format(
                self.get_wheel_platform_tag(arch)
            ))
            file.close()

        env["DIST_EXTRA_CONFIG"] = build_opts
        return env

    def get_wheel_platform_tag(self, arch):
        return f"android_{self.ctx.ndk_api}_" + {
            "armeabi-v7a": "arm",
            "arm64-v8a": "aarch64",
            "x86_64": "x86_64",
            "x86": "i686",
        }[arch.arch]

    def install_wheel(self, arch, built_wheels):
        with patch_wheel_setuptools_logging():
            from wheel.cli.tags import tags as wheel_tags
            from wheel.wheelfile import WheelFile
        _wheel = built_wheels[0]
        built_wheel_dir = dirname(_wheel)
        # Fix wheel platform tag
        wheel_tag = wheel_tags(
            _wheel,
            platform_tags=self.get_wheel_platform_tag(arch),
            remove=True,
        )
        selected_wheel = join(built_wheel_dir, wheel_tag)

        _dev_wheel_dir = environ.get("P4A_WHEEL_DIR", False)
        if _dev_wheel_dir:
            ensure_dir(_dev_wheel_dir)
            shprint(sh.cp, selected_wheel, _dev_wheel_dir)

        info(f"Installing built wheel: {wheel_tag}")
        destination = self.ctx.get_python_install_dir(arch.arch)
        with WheelFile(selected_wheel) as wf:
            for zinfo in wf.filelist:
                wf.extract(zinfo, destination)
            wf.close()

    def build_arch(self, arch):

        build_dir = self.get_build_dir(arch.arch)
        if not (isfile(join(build_dir, "pyproject.toml")) or isfile(join(build_dir, "setup.py"))):
            warning("Skipping build because it does not appear to be a Python project.")
            return

        self.install_hostpython_prerequisites(
            packages=["build[virtualenv]", "pip", "setuptools", "patchelf"] + self.hostpython_prerequisites
        )
        self.patch_shebangs(self._host_recipe.site_bin, self.real_hostpython_location)

        env = self.get_recipe_env(arch, with_flags_in_cc=True)
        # make build dir separately
        sub_build_dir = join(build_dir, "p4a_android_build")
        ensure_dir(sub_build_dir)
        # copy hostpython to built python to ensure correct selection of libs and includes
        shprint(sh.cp, self.real_hostpython_location, self.ctx.python_recipe.python_exe)

        build_args = [
                         "-m",
                         "build",
                         "--wheel",
                         "--config-setting",
                         "builddir={}".format(sub_build_dir),
                     ] + self.extra_build_args

        built_wheels = []
        with current_directory(build_dir):
            shprint(
                sh.Command(self.ctx.python_recipe.python_exe), *build_args, _env=env
            )
            built_wheels = [realpath(whl) for whl in glob.glob("dist/*.whl")]
        self.install_wheel(arch, built_wheels)



class RustCompiledComponentsRecipe(PyProjectRecipe):
    # Rust toolchain codes
    # https://doc.rust-lang.org/nightly/rustc/platform-support.html
    RUST_ARCH_CODES = {
        "arm64-v8a": "aarch64-linux-android",
        "armeabi-v7a": "armv7-linux-androideabi",
        "x86_64": "x86_64-linux-android",
        "x86": "i686-linux-android",
    }

    call_hostpython_via_targetpython = False

    def get_recipe_env(self, arch, **kwargs):
        env = super().get_recipe_env(arch, **kwargs)

        # Set rust build target
        build_target = self.RUST_ARCH_CODES[arch.arch]
        cargo_linker_name = "CARGO_TARGET_{}_LINKER".format(
            build_target.upper().replace("-", "_")
        )
        env["CARGO_BUILD_TARGET"] = build_target
        env[cargo_linker_name] = join(
            self.ctx.ndk.llvm_prebuilt_dir,
            "bin",
            "{}{}-clang".format(
                # NDK's Clang format
                build_target.replace("7", "7a")
                if build_target.startswith("armv7")
                else build_target,
                self.ctx.ndk_api,
            ),
        )
        realpython_dir = self.ctx.python_recipe.get_build_dir(arch.arch)

        env["RUSTFLAGS"] = "-Clink-args=-L{} -L{}".format(
            self.ctx.get_libs_dir(arch.arch), join(realpython_dir, "android-build")
        )

        env["PYO3_CROSS_LIB_DIR"] = realpath(glob.glob(join(
            realpython_dir, "android-build", "build",
            "lib.*{}/".format(self.python_major_minor_version),
        ))[0])

        info_main("Ensuring rust build toolchain")
        shprint(sh.rustup, "target", "add", build_target)

        # Add host python to PATH
        env["PATH"] = ("{hostpython_dir}:{old_path}").format(
            hostpython_dir=Recipe.get_recipe(
                "hostpython3", self.ctx
            ).get_path_to_python(),
            old_path=env["PATH"],
        )
        return env

    def check_host_deps(self):
        if not hasattr(sh, "rustup"):
            error(
                "`rustup` was not found on host system."
                "Please install it using :"
                "\n`curl https://sh.rustup.rs -sSf | sh`\n"
            )
            exit(1)

    def build_arch(self, arch):
        self.check_host_deps()
        super().build_arch(arch)

class CryptographyRecipe(RustCompiledComponentsRecipe):

    name = 'cryptography'
    version = '46.0.3'
    url = 'https://github.com/pyca/cryptography/archive/refs/tags/{version}.tar.gz'
    depends = ['openssl', 'cffi']

    def get_recipe_env(self, arch, **kwargs):
        env = super().get_recipe_env(arch, **kwargs)
        openssl_build_dir = self.get_recipe('openssl', self.ctx).get_build_dir(arch.arch)
        build_target = self.RUST_ARCH_CODES[arch.arch].upper().replace("-", "_")
        openssl_include = "{}_OPENSSL_INCLUDE_DIR".format(build_target)
        openssl_libs = "{}_OPENSSL_LIB_DIR".format(build_target)
        env[openssl_include] = join(openssl_build_dir, 'include')
        env[openssl_libs] = join(openssl_build_dir)
        return env

recipe = CryptographyRecipe()
