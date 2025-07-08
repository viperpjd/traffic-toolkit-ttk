from setuptools import setup, find_packages

setup(
    name="traffic_toolkit",
    version="0.1",
    description="Modular network traffic generator and sniffer for cybersecurity testing",
    author="Peter Dunn",
    author_email="noreply@example.com",
    url="https://github.com/viperpjd",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "cryptography"
    ],
    entry_points={
        'console_scripts': [
            'traffic-toolkit=main:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.6',
)
