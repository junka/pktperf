
from pathlib import Path
from setuptools import setup

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='pktperf',
    version="0.2.0",
    description="pktgen python scripts",
    author="junka",
    author_email="wan.junjie@fixmail.com",
    packages=["pktperf"],
    package_dir={'pktperf':'pktperf/'},
    entry_points={
        'console_scripts':[
            'pktperf=pktperf.pktperf:main',
        ]
    },
    python_requires=">=3.5",
    long_description=long_description,
    long_description_content_type='text/markdown'
)
