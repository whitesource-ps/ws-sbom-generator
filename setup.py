import setuptools
from ws_sbom_generator._version import __version__, __tool_name__, __description__

ws_name = f"ws_{__tool_name__}"

setuptools.setup(
    name=ws_name,
    entry_points={
        'console_scripts': [
            f'{ws_name}={ws_name}.{__tool_name__}:main'
        ]},
    version=__version__,
    author="WhiteSource Professional Services",
    author_email="ps@whitesourcesoftware.com",
    description=__description__,
    url=f"https://github.com/whitesource-ps/{ws_name.replace('_', '-')}",
    license='LICENSE.txt',
    packages=setuptools.find_packages(),
    python_requires='>=3.7',
    install_requires=[line.strip() for line in open("requirements.txt").readlines()],
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
