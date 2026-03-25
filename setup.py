from setuptools import setup, find_packages

setup(
    name="domainspyder",
    version="1.0.0",
    description="Subdomain Enumeration CLI Tool",
    author="Amaan Khan",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "dnspython",
        "rich"
    ],
    entry_points={
        "console_scripts": [
            "domainspyder=domainspyder.cli:main"
        ]
    },
    python_requires=">=3.8",
)