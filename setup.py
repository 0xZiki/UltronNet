from setuptools import setup, find_packages

setup(
    name="ultronnet",
    version="2.1.0",
    packages=find_packages(),
    install_requires=[
        "tqdm",
    ],
    entry_points={
        "console_scripts": [
            "ultronnet=ultronnet.cli.parser:main",
        ],
    },
)
