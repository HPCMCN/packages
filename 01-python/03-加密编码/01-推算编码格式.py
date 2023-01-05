# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/1/5 23:22
# file: 01-推算编码格式.py
import codecs
import tkinter as tk

import jieba


# noinspection PyUnusedLocal
class Coder(object):
    """编码推算工具"""
    charsets = [
        "ascii", "big5", "big5hkscs", "cp037", "cp273", "cp424", "cp437", "cp500", "cp720", "cp737", "cp775", "cp850",
        "cp852", "cp855", "cp856", "cp857", "cp858", "cp860", "cp861", "cp862", "cp863", "cp864", "cp865", "cp866",
        "cp869", "cp874", "cp875", "cp932", "cp949", "cp950", "cp1006", "cp1026", "cp1125", "cp1140", "cp1250",
        "cp1251", "cp1252", "cp1253", "cp1254", "cp1255", "cp1256", "cp1257", "cp1258", "euc_jp", "euc_jis_2004",
        "euc_jisx0213", "euc_kr", "gb2312", "gbk", "gb18030", "hz", "iso2022_jp", "iso2022_jp_1", "iso2022_jp_2",
        "iso2022_jp_2004", "iso2022_jp_3", "iso2022_jp_ext", "iso2022_kr", "latin_1", "iso8859_2", "iso8859_3",
        "iso8859_4", "iso8859_5", "iso8859_6", "iso8859_7", "iso8859_8", "iso8859_9", "iso8859_10", "iso8859_11",
        "iso8859_13", "iso8859_14", "iso8859_15", "iso8859_16", "johab", "koi8_r", "koi8_t", "koi8_u", "kz1048",
        "mac_cyrillic", "mac_greek", "mac_iceland", "mac_latin2", "mac_roman", "mac_turkish", "ptcp154", "shift_jis",
        "shift_jis_2004", "shift_jisx0213", "utf_32", "utf_32_be", "utf_32_le", "utf_16", "utf_16_be", "utf_16_le",
        "utf_7", "utf_8", "utf_8_sig",
    ]

    def __init__(self):
        self.win = tk.Tk()
        self.win.title("全量解码工具 -- HPCMCN")
        self.win.geometry("500x300")

        self.v1 = tk.BooleanVar(self.win)
        self.ch = tk.Checkbutton(self.win, variable=self.v1, text="仅解中文")
        self.ch.pack()

        self.t1 = tk.Text(self.win, height=2)
        self.t1.bind("<KeyRelease>", self.input_event)
        self.t1.pack()

        self.t2 = tk.Text(self.win, height=18)
        self.t2.pack()

    @staticmethod
    def is_chinese(keyword):
        """检测Unicode, 编码是否在指定范围, 来判断是否是常见中文, 而不是乱码或者偏僻字符
        :param keyword: 需要判断的字符串
        :return Bool
        """
        for ch in keyword:
            if not ('\u4e00' <= ch <= '\u9fff'):
                return False
        str_len = len(keyword)
        seg_len = len(jieba.lcut(keyword))
        if str_len / seg_len:
            return True
        else:
            return False

    def decode(self, data, tp=False):
        """遍历Python支持的所有字符集, 来对bytes进行解码
        :param data: str, 需要解码的bytes
        :param tp: bool, 是否只显示中文, False/全部现实
        :return list, 每个解码信息及结果集合
        """
        choices = [f"原数据: {data}\n"]
        try:
            ud = {}
            exec(f"a = b'{data}'", ud)
            a = ud["a"]
            choices.append(f"二进制流数据: {a}\n\n------------- 解码信息 ---------- \n")
            for cs in self.charsets:
                try:
                    x = codecs.decode(a, cs)
                    if tp and not self.is_chinese(x):
                        continue
                    choices.append(f"{cs}\t==> {x}")
                except (UnicodeError, TypeError):
                    pass
            if not choices:
                return choices.append("解析失败!")
            return choices
        except ValueError:
            return choices.append("base64 解码失败!")

    def input_event(self, event):
        """检测用户输入数据, 并且及时刷新输入和解析数据"""
        data = self.t1.get("0.0", "end").strip()
        tp = self.v1.get()
        x = self.decode(data, tp)
        self.t2.delete("0.0", tk.END)
        for j in x or []:
            self.t2.insert("end", j + "\n")
        self.t2.update()

    def main(self):
        """入口函数"""
        self.win.mainloop()


if __name__ == '__main__':
    c = Coder()
    c.main()
