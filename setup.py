import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='dirb_in_py',
    version='0.0.1',
    license="MIT license",
    author='Nikolay Mladenov',
    author_email='nidenov@gmail.com',
    url='https://github.com/Mladia/dirbpy',
    description='Variantion of dirb in py',
    platforms=["unix", "linux", "osx"],
    long_description=long_description,
    long_description_content_type='text/x-rst',
    packages=[
        "dirb_in_py"
    ],
    # package_dir={"": "dirb_in_py"},
    install_requires=[
        "argparse",
        "requests",
        "JSON-log-formatter",
        "xml-python",
        # "logging",
        "urllib3",
        # "multiprocessing",
        "glob2",
        # "os-sys"
    ],
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    # py_modules=["dirb_in_py"],
    zip_safe=False,
)

