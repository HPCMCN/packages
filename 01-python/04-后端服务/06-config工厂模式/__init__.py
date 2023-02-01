# -*- coding:utf-8 -*-
# author:HPCM
# datetime:2019/7/15 14:50
from config.load.load_logging import SettingLogging
from config.load.load_status_code import StatusCode
from config.conf import DEBUG

if DEBUG is True:
    from config.location import constants
else:
    from config.product import constants
