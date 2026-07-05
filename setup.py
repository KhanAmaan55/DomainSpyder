from setuptools import setup, find_packages

setup(
    name="domainspyder",
    version="0.8.0",
    description="Domain Intelligence Framework",
    author="Amaan Khan",
    packages=find_packages(),
    include_package_data=True,
    package_data={"domainspyder": ["assets/img/*.png"]},
    install_requires=[
        "requests",
        "httpx",
        "dnspython",
        "rich",
        "python-whois",
    ],
    entry_points={
        "console_scripts": [
            "domainspyder=domainspyder.cli:main",
        ],
    },
    python_requires=">=3.8",
)
