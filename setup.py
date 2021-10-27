import os
import setuptools

tool_name = 'sbom_generator'

setuptools.setup(
    name=f"ws_{tool_name}",
    entry_points={
        'console_scripts': [
            f'{tool_name}={tool_name}.{tool_name}:main'
        ]},
    version=exec(open(os.path.join(tool_name, '_version.py'), 'r').read().strip()),
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
