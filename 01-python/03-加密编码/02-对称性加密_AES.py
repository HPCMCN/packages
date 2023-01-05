# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/1/5 23:35
# file: 02-对称性加密_AES.py
import time
import random
import base64

try:
    # noinspection PyUnresolvedReferences
    from Crypto.Cipher import AES
except ImportError:
    # noinspection PyUnresolvedReferences
    from Cryptodome.Cipher import AES


class Encryption(object):
    """AES对称加密"""

    def __init__(self, key=None, mode=None):
        # 将秘钥补齐16位
        self.key = self.split_16(key or "wfw7T185V4rtsq").encode()
        self.mode = mode or AES.MODE_CBC
        self.aes = None

    def encrypt(self, content):
        """
        加密
        :param content: str, 需要加密的数据
        :return: str, 加密后的数据
        """
        # 注意由于aes加密后会出现一些无法编码的字符, 使用base64进行编码后在保存
        s = str(random.uniform(0, 1))[:3]
        e = str(int(time.time()))[-5:]
        self.aes = AES.new(self.key, self.mode, self.key)
        return base64.b64encode(self.aes.encrypt(self.add_16(s + "#" + content + "#" + e).encode())).decode()

    def decrypt(self, encrypt_content, start_offset=0, timeout=None):
        """
        解密数据
        :param encrypt_content:加密的信息
        :param start_offset: 秘钥允许使用时间
        :param timeout: 秘钥允许使用时间
        :return: 解密后数据
        """
        self.aes = AES.new(self.key, self.mode, self.key)
        content = self.aes.decrypt(base64.b64decode(encrypt_content)).decode().strip()
        if start_offset and timeout and not start_offset < int(str(int(time.time()))[-5:]) - int(
                content[content.rindex("#") + 1:]) < timeout:
            raise TimeoutError("身份标识已过期!")
        return content[content.index("#") + 1:content.rindex("#")]

    @staticmethod
    def split_16(content):
        """
        切割到长度为16位
        :param content: str, 需要截取或补充的str
        :return: str, 16位长度的字符串
        """
        return content[:16] if content and len(content) > 15 else content.ljust(16)

    @staticmethod
    def add_16(content):
        """
        将传入的参数增加到16的倍数
        :param content: str, 需要操作的str
        :return: str, 能被16整除的str
        """
        d, n = divmod(len(content), 16)
        return content.ljust(16 * (d + (n and 1)))


crypt = Encryption()

if __name__ == "__main__":
    crypt = Encryption()
    txt = crypt.encrypt("xxx")
    print(txt)
    print(crypt.decrypt("guy4zdKZuAKUpY3OD/KdeUU0pjcCJkXbVGTwLnoKwws="))
