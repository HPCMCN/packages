# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/2/1 15:00
# file: 04-isdangerous实现.py
import json
import base64
import time
from hashlib import sha256


class GenJWT(object):
    """json web token"""

    def __init__(self, secret_key, data, encoding="utf-8"):
        self.secret_key = secret_key
        self.data = data
        self._header = None
        self._body = None
        self._sha_value = None
        self.encoding = encoding
        self.time = None

    def get_token(self):
        """获取token"""
        self.make()
        return "{}.{}.{}".format(self.header.decode(self.encoding), self.body.decode(self.encoding),
                                 self.sha_value)

    def make(self):
        """开始制作"""
        self.make_body()
        self.make_sha_value()
        self.make_header()

    def make_header(self):
        """头部信息"""
        header = {
            "length": len(self.body),
            "method": "sha256"
        }
        self._header = base64.b64encode(json.dumps(header).encode(self.encoding))

    def make_body(self):
        """容器信息"""
        self.time = int(time.time())
        data = {
            "data": self.data,
            "time": self.time
        }
        self._body = base64.b64encode(json.dumps(data, sort_keys=lambda x: x).encode(self.encoding))
        print(self._body)

    def make_sha_value(self):
        """sha256值"""
        salt = "{}{}".format(self.secret_key, self.time)
        print(salt)
        s = sha256(salt.encode(self.encoding))
        s.update(self.body)
        self._sha_value = s.hexdigest()

    @property
    def header(self):
        """获取头部信息"""
        return self._header

    @property
    def body(self):
        """获取容器内容"""
        return self._body

    @property
    def sha_value(self):
        """获取sha256值"""
        return self._sha_value


class ParseJWT(object):
    """解析token"""

    def __init__(self, secret_key, data, expire=30, encoding="utf-8"):
        self.secret_key = secret_key
        self.data = data
        self.encoding = encoding
        self._temp_header = None
        self._temp_body = None
        self._temp_sha_value = None
        self._header = None
        self._body = None
        self.time = None
        self.expire = expire

    def verify_token(self):
        """开始解析"""
        value = self.data.split(".")
        if len(value) != 3:
            raise ValueError("token被修改!")
        self._temp_header, self._temp_body, self._temp_sha_value = value
        if self.parse_body() is not True:
            print("body")
            return False
        if self.parse_header() is not True:
            print("header")
            return False
        if self.parse_sha_value() is not True:
            print("sha_value")
            return False
        return True

    def parse_header(self):
        """解析头部"""
        header_value = base64.b64decode(self._temp_header).decode(self.encoding)
        self._header = json.loads(header_value)
        length = self._header.get("length", None)
        method = self._header.get("method", None)
        if not all([length, method, method == "sha256", length == len(self._temp_body)]):
            print("headers")
            return False
        return True

    def parse_body(self):
        """解析容器"""
        body_value = base64.b64decode(self._temp_body).decode(self.encoding)
        self._body = json.loads(body_value)
        try:
            self.time = int(self._body.get("time", None))
        except ValueError:
            return False
        if not all([self.time]):
            print("params")
            return False
        if time.time() - self.time >= self.expire:
            print("time")
            return False
        return True

    def parse_sha_value(self):
        """校验sha256值"""
        salt = "{}{}".format(self.secret_key, self.time)
        print(self._body)
        self._body = base64.b64encode(json.dumps(self._body, sort_keys=lambda x: x).encode(self.encoding))
        print(salt)
        s = sha256(salt.encode(self.encoding))
        s.update(self._body)
        sha_value = s.hexdigest()
        if sha_value != self._temp_sha_value:
            return False
        return True

    @property
    def header(self):
        """头部信息"""
        return self._header

    @property
    def body(self):
        """容器信息"""
        return self._body


if __name__ == '__main__':
    secret_key = "sadiofasoidfnp"
    data = {
        "user": "aaa",
        "pass": "bbb"
    }

    gjwt = GenJWT(secret_key, data)
    token = gjwt.get_token()
    print("生成token: ", token)

    time.sleep(3)

    pjwt = ParseJWT(secret_key, token, expire=4)
    print("验证token: ", pjwt.verify_token())
    print("token body: ", pjwt.body)
