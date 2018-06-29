import setuptools

#with open("README.md", "r") as fh:
#    long_description = fh.read()

setuptools.setup(
    name="fortelib",
    version="0.0.1",
    author="forte-bin",
    author_email="forte.bin@gmail.com",
    description="A collection of utility functions",
    long_description=description,
    long_description_content_type="text/markdown",
    url="https://github.com/forte-bin/fortelib",
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)