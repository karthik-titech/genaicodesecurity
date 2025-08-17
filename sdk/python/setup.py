from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="google-home-security-patch",
    version="1.0.0",
    author="Google Home Security Patch Team",
    author_email="security@yourcompany.com",
    description="Python SDK for Google Home Security Patch API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/google-home-security-patch",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.0.0",
            "black>=21.0.0",
            "flake8>=3.8.0",
            "mypy>=0.800",
        ],
    },
    keywords="google-home, security, api, sdk, smart-home, cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/your-repo/google-home-security-patch/issues",
        "Source": "https://github.com/your-repo/google-home-security-patch",
        "Documentation": "https://docs.your-domain.com",
    },
)
