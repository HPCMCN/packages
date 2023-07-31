# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/2/18 1:35
# file: chrome_cookies.py
import os
import sys
import json
import psutil
import shutil
import base64
import sqlite3

import win32crypt
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


def get_key():
    with open(os.getenv("APPDATA") + "/../Local/Google/Chrome/User Data/Local State", 'r', encoding="utf-8") as file:
        encrypted_key = json.loads(file.read())['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key)
    encrypted_key = encrypted_key[5:]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]


def decrypt(decrypted_key, encrypted_value):
    try:
        # Try to decrypt as AES (2020 method)
        cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce=encrypted_value[3:3 + 12])
        decrypted_value = cipher.decrypt_and_verify(encrypted_value[3 + 12:-16], encrypted_value[-16:])
    except:
        # If failed try with the old method
        decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8')
    return decrypted_value.decode()


def get_cookies(url):
    decrypted_key = get_key()
    cookies = []
    for proc in psutil.process_iter():
        if "chrome" in proc.name():
            try:
                for x in proc.open_files():
                    if x.path.endswith("Cookies") and "Network" in x.path:
                        psutil.Process(proc.pid).terminate()
            except psutil.AccessDenied:
                pass
    if sys.platform == 'win32':
        cookies_path = os.getenv("APPDATA") + "/../Local/Google/Chrome/User Data/Default/Network/Cookies"
    elif sys.platform == 'linux':
        cookies_path = "~/Chrome/Cookies"
    else:
        raise OSError('This tool is only supported by linux and Mac')
    conn = sqlite3.connect(cookies_path)
    cursor = conn.cursor()
    cursor.execute('SELECT name, value, encrypted_value FROM cookies WHERE host_key == "' + url + '"')
    for name, value, encrypted_value in cursor.fetchall():
        dv = decrypt(decrypted_key, encrypted_value) or value or 0
        cookies.append((name, dv))
    conn.close()
    return cookies


if __name__ == '__main__':
    print("; ".join([f"{k}={v}" for k, v in get_cookies('.bilibili.com')]))