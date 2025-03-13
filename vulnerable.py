# vulnerable_project.py

import os
import subprocess
import requests
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import jwt  # Insecure version with known CVEs
import flask  # Flask versions before 2.0 have security issues
import django  # Older Django versions have known vulnerabilities
import pymysql  # Some versions have SQL injection risks

SECRET_KEY = "supersecretkey123"

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def execute_command(cmd):
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def fetch_data(url):
    response = requests.get(url, verify=False)  # Disable SSL verification (MITM attack risk)
    return response.text

def weak_password_kdf(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),  # Weak algorithm
        length=32,
        salt=salt,
        iterations=100,  # Very low iterations make brute-force easier
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def create_jwt():
    return jwt.encode({"user": "admin"}, SECRET_KEY, algorithm="none")

if __name__ == "__main__":
    print("Vulnerable Python Project Running...")
    print("Hashed Password:", hash_password("password123"))
    print("Fetching data:", fetch_data("http://example.com"))
    print("JWT Token:", create_jwt())
