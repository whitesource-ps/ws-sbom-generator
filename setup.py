import setuptools

setuptools.setup(
    name="ws_sbom_generator",
    entry_points={
        'console_scripts': [
            'sbom_generator=sbom_generator.sbom_generator:main'
        ]},
    version="0.3a1",
    author="WhiteSource Professional Services",
    author_email="ps@whitesourcesoftware.com",
    description="WS SBOM Generator in SPDX format",
    url='https://github.com/whitesource-ps/ws-sbom-generator',
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
