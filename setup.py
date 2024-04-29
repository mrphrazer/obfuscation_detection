import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="obfuscation_detection",
    version="2.1",
    author="Tim Blazytko",
    author_email="tim@blazytko.to",
    description="Binary Ninja plugin to identify obfuscated code and other interesting code constructs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mrphrazer/obfuscation_detection",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: POSIX :: Linux",
    ],
    packages=setuptools.find_packages(),
    python_requires='>=3.9',
)