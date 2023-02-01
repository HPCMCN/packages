# -*- coding:utf-8 -*-
# author:HPCM
# datetime:2019/7/15 14:21
import json
import logging.config

from .load_path import LoadPath
from config import conf


class SettingLogging(LoadPath):
    """导入并处理日志配置"""

    def __init__(self, base_dir, config_file=None):
        self.config_file = config_file or conf.CONFIG_LOGGING_PATH
        super().__init__(base_dir)

    def set_logger(self):
        """配置日志"""
        logging_path = self.absolute_path(self.config_file)
        with open(logging_path, "r") as f:
            setting_logger = json.load(f)
            logging_file = setting_logger.get("handlers").get("file").get("filename")
            setting_logger["handlers"]["file"]["filename"] = self.absolute_path(logging_file)
            logging.config.dictConfig(setting_logger)
