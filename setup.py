import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='dirbpy',
    version='1.2.15',
    author='Marc-Olivier Bouchard',
    author_email='mo.bouchard1997@gmail.com',
    url='https://github.com/marcolivierbouch/dirbpy',
    description='This is the new version of dirb in python.',
    platforms=["unix", "linux", "osx"],
    scripts=["bin/dirbpy"],
    long_description=long_description,
    long_description_content_type='text/x-rst',
    packages=[
        "_dirbpy",
    ],
    package_dir={"": "src"},
    install_requires=[
        "argparse",
        "requests",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: OS Independent",
    ],
    py_modules=["dirbpy"],
    zip_safe=False,
)

