""" install pktgen module maybe bdist instead
"""
import subprocess
from setuptools import setup
from setuptools.command.install import install


class CustomInstall(install):
    """ CustomInstall to build pktgen from source when install
    """
    def run(self):
        with subprocess.Popen(
            ["make", "-C", "pktperf/module", "install"], shell=False
        ) as process:
            process.wait()
        super().run()


setup(
    name= 'pktperf',
    version = "0.5.7",
    has_ext_modules=lambda: True,
    cmdclass={"install": CustomInstall},
    platforms=["manylinux2014_x86_64"],
)
