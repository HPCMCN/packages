# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/2/1 14:40
# file: 03-小米监控视频合并.py
import os
import time

import cv2

# 使用m3u8文件组合ts文件
m3u8_file_name = r"C:\Users\hpcm\Desktop\48320843682424960\48320843682424960_plain.m3u8"
base_path = os.path.dirname(m3u8_file_name)
new_file_name = str(time.time()) + ".mp4"


def find_all_ts():
    """获取全部ts文件"""
    files = []
    with open(m3u8_file_name, "r") as f:
        for content in f:
            content = content.strip()
            if content.endswith(".ts"):
                files.append(os.path.join(base_path, os.path.basename(content)))
    return files


def add_video(files):
    """组合视频"""
    rb = os.path.join(base_path, "test.mp4")
    r_v = cv2.VideoWriter(rb, cv2.VideoWriter_fourcc(*'mp4v'), 19, (2304, 1296))

    for i, file in enumerate(files):
        print(file, "{:.2f}".format(i + 1 / len(files)))
        b_v = cv2.VideoCapture(file)
        while True:
            ret, frame = b_v.read()

            if ret is True:
                # try:
                #     cv2.imshow('frame', frame)
                # except:
                #     pass
                r_v.write(frame)
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
            else:
                break

        b_v.release()
    r_v.release()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    files = find_all_ts()
    add_video(files)
    print("success!")
