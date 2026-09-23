from setuptools import setup, find_packages

setup(
    name="domainspyder",
    version="0.9.0",
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
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "pytest-mock>=3.0",
            "responses>=0.23",
            # Pinned: these gate CI, and a minor bump can widen
            # the default rule set or change the formatting style.
            "ruff>=0.16,<0.17",
            "black>=25.11,<27.0",
            "mypy>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "domainspyder=domainspyder.cli:main",
        ],
    },
    python_requires=">=3.9",
)
