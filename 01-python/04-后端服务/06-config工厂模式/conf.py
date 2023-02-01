# -*- coding:utf-8 -*-
# author:HPCM
# datetime:2019/7/12 10:18
import os

DEBUG = True

# **************************** 基础参数配置 ****************************
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# **************************** 路径参数配置 ****************************
CONFIG_LOGGING_PATH = "config/common/logging.json"  # logging配置路径
CONFIG_STATUS_CODE_PATH = "config/common/status.yaml"  # 状态码配置路径
CONFIG_HOLIDAY_CSV_PATH = "config/scripts/holiday.csv"  # 节假日csv文件
SEND_MASSAGE_FILE = "scripts/massage.txt"  # 发送微信信息的临时保存
