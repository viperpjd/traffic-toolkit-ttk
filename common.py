"""
Author: Peter Dunn
License: MIT
GitHub: https://github.com/viperpjd
LinkedIn: https://www.linkedin.com/in/pdunncs/
Description: Part of the Traffic Toolkit for network and security testing.
"""

# common.py
import random

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0xff) for _ in range(5))

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def random_port():
    return random.randint(1024, 65535)
