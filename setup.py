import setuptools

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()

setuptools.setup(
    name="securepickle",
    version="0.0.0",
    install_requires=[],
    description="Tools for secured pickling",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/goncalopp/securepickle",
    packages=setuptools.find_packages(),
    tests_require=[],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2",
        "Operating System :: OS Independent",
    ],
)
