# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/1/5 23:12
# file: 01-网速检测.py
import time
import tkinter as tk

import psutil


# noinspection PyUnresolvedReferences
class NetSpeed(tk.Frame):
    """网速检测"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.speed = tk.StringVar()
        self.base_win()
        self.net_work = None

    def base_win(self):
        """创建标题"""
        lb = tk.Label(self, textvariable=self.speed)
        lb.pack()

    def refresh(self):
        """刷新网速数据"""
        while True:
            self.now_speed()
            time.sleep(1)

    def now_speed(self):
        """计算当前网速指标"""
        sent, recv = self.net_speed()
        length = len(sent) - len(recv)
        s_l = " " * abs(length) if length > 0 else ""
        r_l = " " * abs(length) if length < 0 else ""
        speed = "\n\n上传: {}{}\n下载: {}{}".format(s_l, sent, r_l, recv)
        self.speed.set(speed)

    def start(self):
        """启动中心"""
        t = Thread(target=self.refresh)
        t.start()
        self.pack()

    def get_network(self):
        """利用网速波动, 来确定需要监听网口"""
        for key, value in psutil.net_io_counters(pernic=True).items():
            print(key)
            if self.net_work is not None:
                return self.net_work
            elif key == "WLAN":
                return key
            # if value.bytes_recv and value.bytes_sent and key != "lo":
            #    return key

    def net_speed(self):
        """获取指定网口的流量信息"""
        if self.net_work is None:
            self.net_work = self.get_network()
        net = psutil.net_io_counters(pernic=True).get(self.net_work)
        s_r = net.bytes_recv
        s_s = net.bytes_sent
        t = 1
        time.sleep(t)
        net = psutil.net_io_counters(pernic=True).get(self.net_work)
        e_r = net.bytes_recv
        e_s = net.bytes_sent
        sent = e_s - s_s
        recv = e_r - s_r
        return [(lambda a: "{:.2f}kb/s".format(a / 1024) if a < 1024 * 999 else "{:.2f} M/s".format(a / 1024 / 1024))(a)
                for a in (sent, recv)]


if __name__ == "__main__":
    from threading import Thread

    root = tk.Tk()
    root.wm_attributes('-topmost', 1)  # 锁定窗口置顶
    root.wm_attributes('-topmost', 1)
    root.geometry('250x150')
    root.title("网速检测")
    ns = NetSpeed(root)
    ns.start()
    root.mainloop()
