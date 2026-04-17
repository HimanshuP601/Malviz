import psutil
import hashlib
import ctypes
import re
import os

def test_hash():
    try:
        with open(r"c:\windows\system32\notepad.exe", "rb") as f:
            data = f.read()
            return hashlib.sha256(data).hexdigest()
    except Exception as e:
        return str(e)

def test_strings():
    try:
        with open(r"c:\windows\system32\notepad.exe", "rb") as f:
            data = f.read()
            ascii_strings = re.findall(b'[ -~]{5,}', data)
            unicode_strings = re.findall(b'(?:[ -~]\x00){5,}', data)
            return len(ascii_strings), len(unicode_strings)
    except Exception as e:
        return str(e)

def test_psutil():
    try:
        p = psutil.Process()
        files = p.open_files()
        threads = p.threads()
        return len(files), len(threads)
    except Exception as e:
        return str(e)

print("Hash:", test_hash())
print("Strings:", test_strings())
print("Resources:", test_psutil())
