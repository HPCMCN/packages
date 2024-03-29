# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/2/1 14:54
# file: 01-网卡切换.py
import socket
import urllib3.connection
import requests

_default_create_socket = socket.create_connection
_urllib3_create_socket = urllib3.connection.connection.create_connection
local_hosts = ["11.11.12.10", "11.11.11.10"]


def default_create_socket(*args, **kwargs):
    """增加网卡轮询功能"""
    try:
        del kwargs["socket_options"]
    except:
        pass
    in_args = False
    for host in local_hosts:
        if len(args) >= 3:
            args = list(args)
            args[2] = host, 0
            args = tuple(args)
            in_args = True
        if not in_args:
            kwargs["source_address"] = host, 0
        print("default_create_connection args", args)
        print("default_create_connection kwargs", str(kwargs))
        try:
            sock = _default_create_socket(*args, **kwargs)
            return sock
        except BaseException as e:
            print(e)
            import traceback
            traceback.print_exc()
        time.sleep(1)
    else:
        raise ConnectionError


def urllib3_create_socket(*args, **kwargs):
    """增加网卡轮询功能"""
    try:
        del kwargs["socket_options"]
    except:
        pass
    in_args = False
    for host in local_hosts:
        if len(args) >= 3:
            args = list(args)
            args[2] = host, 0
            args = tuple(args)
            in_args = True
        if not in_args:
            kwargs["source_address"] = host, 0
        print("default_create_connection args", args)
        print("default_create_connection kwargs", str(kwargs))
        try:
            sock = _urllib3_create_socket(*args, **kwargs)
            return sock
        except BaseException as e:
            import traceback
            traceback.print_exc()
            time.sleep(1)
    else:
        raise ConnectionError


socket.create_connection = default_create_socket
urllib3.connection.connection.create_connection = urllib3_create_socket

while True:
    print(requests.get("http://39.98.35.196:8102/", timeout=2).content)
    import time

    time.sleep(2)
