# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/2/1 14:55
# file: 02-本机IP获取.py
def get_host_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip
