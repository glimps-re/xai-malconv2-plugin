import os
import shutil
import logging
import sys
import time
from pathlib import Path
import ida_diskio
import importlib.util

logger = logging.getLogger(__name__)

REPOSITORY_ROOT = Path(__file__).parent.resolve()


def is_plugin_installed():
    """Check if plugin and required dependencies are installed."""
    return (
        importlib.util.find_spec("malconv2") is not None
        and importlib.util.find_spec("numpy") is not None
    )


IGNORED_EXT = ["pyc", "md", "gitignore", "txt"]


def install_files(src, plugin_directory, content_only):
    def ignore_file(name):
        return any([name.endswith("." + ext) for ext in IGNORED_EXT])

    def ignore_files(_, names):
        ignored = [n for n in names if ignore_file(n)]
        logger.info("Ignored files : %r" % ignored)
        return ignored

    if content_only:
        for fpath in src.glob("*"):
            if fpath.is_dir():
                target = plugin_directory / fpath.name
                logger.info("Copying directory %s to %s", fpath, target)
                try:
                    shutil.rmtree(target)
                except Exception as _err:
                    pass
                time.sleep(0.1)

                shutil.copytree(fpath, target, ignore=ignore_files)
            elif not ignore_file(fpath):
                target = plugin_directory / fpath.name
                logger.info("Copying file %s to %s", fpath, plugin_directory)
                try:
                    target.unlink()
                except Exception as _err:
                    pass

                shutil.copy(fpath, target)
    else:
        target = plugin_directory / src.name
        logger.info("Copying %s to %s", src, target)
        try:
            shutil.rmtree(target)
        except Exception as _err:
            pass
        shutil.copytree(src, target, ignore=ignore_files)


def _is_path_writable(input_path):
    test_path = Path(input_path) / "_tmp_write_test"
    try:
        if not input_path.exists():
            input_path.mkdir()
        test_path.mkdir()
        test_path.rmdir()
        return True
    except Exception as _err:
        return False


def _is_path_userconfig(input_path):
    return "/.idapro" in str(input_path)


def _get_install_directory():
    plugin_directories = ida_diskio.get_ida_subdirs("plugins")
    if os.name == "nt":
        for pdir in plugin_directories:
            if _is_path_writable(pdir):
                return pdir
                break
        logger.error("Could not find a writable path for plugin installation")
    elif os.name == "posix":
        for pdir in plugin_directories:
            pdir = Path(pdir)
            if _is_path_userconfig(pdir):
                if not pdir.exists():
                    pdir.mkdir(parents=True)
                return pdir
                break
        for pdir in plugin_directories:
            if _is_path_writable(pdir):
                return pdir
                break
        logger.error("Could not find a writable path for plugin installation")
    return False


def _get_current_installation_directory():
    plugin_directories = ida_diskio.get_ida_subdirs("plugins")
    for pdir in plugin_directories:
        plugin_py = Path(pdir) / "ida-plugin-malconv2"
        if plugin_py.exists():
            return pdir
    return None


def install_plugin():
    plugin_directory = _get_install_directory()

    current_installation = _get_current_installation_directory()
    if current_installation:
        if Path(plugin_directory).absolute() != Path(current_installation).absolute():
            logger.error(
                "Current installation is in a forbidden directory (%s). Please manually uninstall the plugin, and reinstall using the correct procedure.",
                current_installation,
            )
            return False

    libs_root = REPOSITORY_ROOT / "malconv2"
    install_files(libs_root, plugin_directory, content_only=False)
    shutil.copy(REPOSITORY_ROOT / "malconv2.py", plugin_directory / "malconv2.py")

    if plugin_directory not in sys.path:
        sys.path.append(plugin_directory)

    if is_plugin_installed():
        logger.warning(
            "Code Plugin installed. Please install required python packages (Cf. requirements.txt)"
        )
        logger.warning(
            "And ensure that IDA uses the same Python installation, then restart IDA."
        )
    else:
        logger.error("Error during installation, code plugin not reachable.")


if __name__ == "__main__":
    install_plugin()
