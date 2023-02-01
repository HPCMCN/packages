# -*- coding:utf-8 -*-
# author:HPCM
# datetime:2019/7/22 10:09
# **************************** redis参数配置 ****************************
REDIS_USER_LINK_HOST = "199.0.1.175"
REDIS_USER_LINK_PORT = 6001

# **************************** redis参数配置 ****************************
ORACLE_TRADING_HOST = "19.19.19.192"
ORACLE_TRADING_PORT = 1521
ORACLE_TRADING_USERNAME = "gessfesc"
ORACLE_TRADING_PASSWORD = "gessfesc"
ORACLE_TRADING_DATABASE = "gess"

SQL_TRADING_VOLUME = "Select sum(t.exch_bal) From gessfesc.busi_back_flow t"

# **************************** 节假日参数配置 ****************************
HOLIDAY_SIGN_LIST = ["S", "H"]  # 节假日标志

# **************************** 微信接口配置 ****************************
WX_FORMER_API = "http://199.0.1.160/"
WX_FORMER_TOKEN = "KzaJBYgwAy0w+TMGbqZJ0uBq/g/zk32McBrdRoAgFiv6edoPi56lFBe+1Oy55wTA"
WX_ROBOT_KEY = "1589deed-bde8-426d-9efd-ce3f8c893b63"
# WX_ROBOT_KEY = "32b34f4a-7f82-4756-9608-3c79f39fec23"

# **********************天融信防火墙命令查询**************************
# 查询时间信息
TRX_CURRENT_TIME = "system time show"
# 查询流量信息
TRX_NETWORK_INTERFACE = "network interface show"

# **********************账号密码加密**********************************
# 字典内部格式:   ip: [账号, 密码, 名称, 外网网卡编号]
HOST_INFO_DICT = {
    "199.0.1.244:22": ["yebin", "Aa123456", "移动", ["2", "4"]],
    "199.0.1.246:22": ["yebin", "Aa123456", "电信", ["2", "3"]],
    "199.0.1.247:22": ["yebin", "Aa123456", "联通", ["2", "4"]]
}
# 限制获取网络流量的时间段
LIMIT_START_END_TIME_LIST = [
    # ("20:00:00", "20:24:00"),
    ("20:00:00", "20:24:00"),
]