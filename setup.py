""" setup for project """
from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='pktperf',
    version="0.4.0",
    description="pktgen python scripts",
    author="junka",
    author_email="wan.junjie@fixmail.com",
    packages=["pktperf"],
    package_dir={'pktperf': 'pktperf/'},
    entry_points={'console_scripts': [
        'pktperf=pktperf.pktperf:main',
    ]},
    python_requires=">=3.5",
    long_description=long_description,
    long_description_content_type='text/markdown',
    project_urls={
        "Bug Tracker": "https://github.com/junka/pktperf/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
    ],
)
