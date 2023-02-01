# -*- coding:utf-8 -*-
# author:HPCM
# datetime:2019/7/15 15:27
import os


class LoadPath(object):
    """导入并处理日志配置"""
    def __init__(self, base_dir):
        self.base_dir = base_dir

    @staticmethod
    def to_abs_path(current_path):
        """规整路径"""
        return "{}".format(os.sep).join(current_path.split("/"))

    def absolute_path(self, path):
        """获取绝对路径"""
        return os.path.join(self.base_dir, self.to_abs_path(path))
