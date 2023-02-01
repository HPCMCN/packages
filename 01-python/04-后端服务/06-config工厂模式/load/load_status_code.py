# -*- coding:utf-8 -*-
# author:HPCM
# datetime:2019/7/15 15:21
import yaml

from .load_path import LoadPath
from config import conf


class StatusCode(LoadPath):
    """导入并处理日志配置"""

    def __init__(self, base_dir, config_file=None):
        self.status_path = config_file or conf.CONFIG_STATUS_CODE_PATH
        super().__init__(base_dir)
        self.msg = None
        self.load_yaml()

    def load_yaml(self):
        """载入yaml配置"""
        logging_path = self.absolute_path(self.status_path)
        with open(logging_path, "r", encoding="utf-8") as f:
            self.msg = yaml.load(f, Loader=yaml.FullLoader)

    def set_msg(self, code):
        """配置日志"""
        msg = self.msg.get(code, None)
        if msg is None:
            raise ValueError("Status code {} is undefined!".format(code))
        return {
            "code": code,
            "msg": msg
        }
