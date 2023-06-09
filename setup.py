from setuptools import setup
from setuptools.command.install import install
import subprocess


class CustomInstall(install):
    def run(self):
        process = subprocess.Popen(
            ["make", "-C", "pktperf/module", "install"], shell=False
        )
        process.wait()
        super().run()


setup(
    has_ext_modules=lambda: True,
    cmdclass={"install": CustomInstall},
    platforms=["manylinux2014_x86_64"],
)
