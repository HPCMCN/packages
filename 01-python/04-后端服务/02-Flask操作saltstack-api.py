# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/2/1 15:35
# file: 02-Flask操作saltstack-api.py
import os
import json
import time
import base64
import logging

import yaml
import requests

from config import conf, constants
from common import aes_crypt, curd_manager

logger = logging.getLogger("transform")


class SaltAPI(object):
    """salt stack api"""

    def __init__(self):
        self.base_url = constants.SALT_MASTER_URL
        self.username = constants.SALT_MASTER_USERNAME
        self.password = aes_crypt.crypt.decrypt(constants.SALT_MASTER_PASSWORD)
        self.remote_python_filename = constants.REMOTE_EXECFILE_PATH
        self.upload_python_filename = os.path.join(conf.BASE_DIR, constants.LOCAL_EXECFILE_PATH)
        self.headers = {
            "Accept": "application/x-yaml",
        }
        self.retry = 3
        token = self.get_token()
        if not token:
            raise OSError("Login salt-master failed!")
        self.headers["X-Auth-Token"] = token

    def requests_post(self, url, data, parse=True):
        """request and parse yaml data"""
        for _ in range(self.retry):
            try:
                logger.info(f"request ==> {url}")
                res = requests.post(url, headers=self.headers, json=data, verify=False)
                logger.info(f"response[{res.status_code}] <== {res.content}")
                if parse:
                    try:
                        res = yaml.load(res.content, Loader=yaml.SafeLoader)
                    except TypeError:
                        logger.info(res.content)
                return res
            except Exception as e:
                logger.exception(e)

    def requests_get(self, url, parse=True):
        """request and parse yaml data"""
        for _ in range(self.retry):
            try:
                logger.info(f"request ==> {url}")
                res = requests.get(url, headers=self.headers, verify=False)
                logger.info(f"response[{res.status_code}] <== {res.content}")
                if parse:
                    try:
                        res = yaml.load(res.content, Loader=yaml.SafeLoader)
                    except TypeError:
                        logger.info(res.content)
                return res
            except Exception as e:
                logger.exception(e)

    def login_salt(self):
        """login salt-master get token"""
        login_url = self.base_url + "login/"
        data = {
            "eauth": "sharedsecret",
            "username": self.username,
            "password": self.password
        }
        return self.requests_post(login_url, data)

    def get_token(self):
        """get salt token"""
        ost = curd_manager.OSaltTasks.select_obj(idt=0)
        if ost:
            data = json.loads(ost.parse_result or "{}")
            if data and data["expire"] - time.time() - 60 * 60 * 2 > 0:
                return data["token"]
        else:
            kwargs = {"id": 0, "jid": 0, "service_script_id": 0, "has_loop": 0, "task_status": "ready"}
            curd_manager.OSaltTasks.create_token(kwargs)
        res = self.login_salt()
        if not res:
            logger.error("not get response data!")
            return
        curd_manager.OSaltTasks.update({"raw_result": res}, 0)
        expire_time = res["return"][0]["expire"]
        start_time = res["return"][0]["start"]
        token = res["return"][0]["token"]
        data = {"expire": expire_time, "start": start_time, "token": token}
        curd_manager.OSaltTasks.update({"parse_result": data}, 0)
        logger.info(f"token: {token}, [{start_time}, {expire_time}]")
        return token

    def trans(self, arg):
        return arg.replace("=", "\\=")

    def execute_cmd(self, node, arg):
        """execute cmd"""
        run_url = self.base_url
        arg = self.trans(arg)
        data = {
            "client": "local",
            "tgt": node,
            "fun": "cmd.run",
            "arg": arg
        }
        logger.info(data)
        res = self.requests_post(run_url, data)
        if not res:
            logger.error("not get response data!")
            return
        logger.info(res)
        return res["return"][0][node]

    def async_execute_cmd(self, node, arg):
        """async execute cmd"""
        run_url = self.base_url
        arg = self.trans(arg)
        data = {
            "client": "local_async",
            "tgt": node,
            "fun": "cmd.run",
            "arg": arg
        }
        logger.info(data)
        res = self.requests_post(run_url, data)
        if not res:
            logger.error("not get response data!")
            return
        logger.info(res)
        return res["return"][0]

    def cancel_task(self, node, arg):
        """cancel task"""
        run_url = self.base_url
        data = {
            "client": "local",
            "tgt": node,
            "fun": "saltutil.term_job",
            "arg": arg
        }
        logger.info(data)
        res = self.requests_post(run_url, data)
        if not res:
            logger.error("not get response data!")
            return
        logger.info(res)
        return res["return"][0]

    def execute_upload(self, node, src, dst, params=None):
        """execute upload"""
        run_url = self.base_url
        with open(src, "r", encoding="utf-8") as f:
            content = f.read()
        if params:
            for key, value in params.items():
                content = content.replace(key, str(value))
        content = content.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace(
            "\"", "'").replace("\t", "\\t").strip()
        data = {
            "client": "local",
            "tgt": node,
            "fun": "cmd.run",
            "arg": "/salt/bin/python -c \"with open('{}', 'w+') as fp:fp.write('''{}''')\"".format(dst, content)
        }
        logger.info(data)
        res = self.requests_post(run_url, data)
        if not res:
            logger.error("not get response data!")
            return
        logger.info(res)
        return res["return"][0][node]

    def sync_modules(self, host_name):
        """sync modules"""
        run_url = self.base_url
        data = {
            "client": "local",
            "tgt": host_name,
            "fun": "saltutil.sync_modules"
        }
        res = self.requests_post(run_url, data)
        logger.info(res)

    def trans_content(self, content):
        return content.replace("\r", "")

    def repeat_upload_content(self, host_name, filename, content):
        """execute python content"""
        self.sync_modules(host_name)
        run_url = self.base_url
        content = base64.b64encode(self.trans_content(content).encode("utf-8")).decode("utf-8").replace("=", "\\=")
        data = {
            "client": "local",
            "tgt": host_name,
            "fun": "ru.repeat_upload",
            "arg": (filename, content)
        }
        logger.info(data)
        res = self.requests_post(run_url, data)
        logger.info(res)
        # self.execute_remove(host_name, filename)
        if not res:
            logger.error("not get response data!")
        return res["return"][0][host_name]

    def repeat_upload(self, host_name, rf, lf, cmd):
        """execute python content"""
        with open(lf, "rb") as f:
            content = f.read()
        content = base64.b64encode(content).decode("utf-8").replace("=", "\\=")
        return self.repeat_upload_content(host_name, rf, content)

    def execute_remove(self, node, filename):
        """execute remove file"""
        run_url = self.base_url
        data = {
            "client": "local",
            "tgt": node,
            "fun": "file.remove",
            "arg": filename
        }
        return self.requests_post(run_url, data)


# noinspection PyUnresolvedReferences
class SaltLogDownload(SaltAPI):
    """base salt download log file"""

    def __init__(self, downloads=None):
        super(SaltLogDownload, self).__init__()
        self.base_dir = conf.BASE_DIR
        self.ftp_url = constants.FTP_BASE_URL
        self.logging_path = "log"
        self.downloads = downloads
        self.results = {}
        self.paths = []

    def upload_file(self, host_name):
        """upload python file"""
        run_url = self.base_url
        with open(self.upload_python_filename, "r", encoding="utf-8") as f:
            content = f.read().replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\"", "'")
        data = {
            "client": "local",
            "tgt": host_name,
            "fun": "cmd.run",
            "arg": "/salt/bin/python -c \"with open('{}', 'w+') as fp:fp.write('''{}''')\"".format(
                self.remote_python_filename, content)
        }
        logger.info(data)
        res = self.requests_post(run_url, data)
        if not res:
            logger.error("not get response data!")
            return
        logger.info(res)
        if not res["return"][0][host_name]:
            logger.info("python file upload success!")
            return True
        logger.error(res["return"][0][host_name])

    def execute_file(self, host_name, app_path, date):
        """execute python file"""
        run_url = self.base_url
        compress_file = r"C:\\{}_{}_{}.zip".format(host_name, app_path.replace("\\", "_"), date)
        python_params = base64.b64encode("{} {} {}".format(app_path, date, compress_file).encode("utf-8")).decode()
        data = {
            "client": "local",
            "tgt": host_name,
            "fun": "cmd.run",
            # file_name, app_path, date, compress_file
            "arg": r"\salt\bin\python {} {}".format(self.remote_python_filename, python_params)
        }
        logger.info(data)
        res = self.requests_post(run_url, data)
        if not res:
            logger.error("not get response data!")
            return
        logger.info(res)
        result = str(res["return"][0][host_name])
        if result.endswith(".zip"):
            logger.info("compress success: {}".format("".join(res["return"][0][host_name])))
            return compress_file
        elif result.endswith("BufferError"):
            logger.info("zipfile too large!")
            self.results[host_name] = "zipfile too large!"
        else:
            logger.info("execute pyfile failed!")
            self.results[host_name] = "execute pyfile failed!"
        logger.error(f"execute python file failed!")

    def download(self, host_name, remote_file):
        """download compress file"""
        run_url = self.base_url
        data = {
            "client": "local",
            "tgt": host_name,
            "fun": "cp.push",
            "arg": remote_file
        }
        res = self.requests_post(run_url, data)
        if not res:
            logger.error("not get response data!")
            return
        logger.info(res)
        if res["return"][0][host_name]:
            if "\\" in remote_file:
                filename = self.ftp_url.format(host_name, remote_file.replace("\\", "/")[4:])
            else:
                filename = self.ftp_url.format(host_name, remote_file[1:])
            self.results[host_name] = filename
            logger.info("download success!")
            return filename
        else:
            logger.error("download failed!")
            self.results[host_name] = "download failed!"
        logger.info(self.results)

    def rm_tarfile(self, host_name, remote_file):
        """remove logs tar file"""
        run_url = self.base_url
        data = {
            "client": "local",
            "tgt": host_name,
            "fun": "file.remove",
            "arg": remote_file
        }
        res = self.requests_post(run_url, data)
        if not res:
            logger.error("not get response data!")
            return
        logger.info(res)
        if not res["return"][0][host_name]:
            logger.error("remove tarfile failed!")
        else:
            logger.info("tarfile remove success!")

    def start(self):
        """start progress"""
        for download_info in self.downloads:
            name = download_info["name"]
            path = download_info["path"]
            date = download_info["date"]
            if not self.upload_file(name):
                continue
            tarfile = self.execute_file(name, path, date)
            if not tarfile:
                continue
            self.download(name, tarfile)
            self.rm_tarfile(name, tarfile)
        return self.results

    def tar_files(self, host_name, files):
        """compress files"""
        name = f"/root/{host_name}_{int(time.time())}.tar.gz"
        data = {
            "client": "local",
            "tgt": host_name,
            "fun": "cmd.run",
            "arg": "tar -zcf {} {}".format(name, " ".join(files))
        }
        logger.info(data)
        res = self.requests_post(self.base_url, data)
        result = str(res["return"][0][host_name])
        logger.info(result)
        return name

    def list_dir(self, host_name, path):
        """pass"""
        data = {
            "client": "local",
            "tgt": host_name,
            "fun": "cmd.run",
            "arg": f"ls -l {path}"
        }
        logger.info(data)
        res = self.requests_post(self.base_url, data)
        logger.info(res)
        result = str(res["return"][0][host_name])
        logger.info(result)
        if "No such file or directory" not in result:
            info = []
            for line in result.split("\n")[1:]:
                line_info = line.split(maxsplit=8)
                logger.info(line_info[-1])
                file = line_info[-1].split()[0]
                logger.info(file)
                info.append((file, line_info))
            return sorted(info, key=lambda x: x[0])
            # if len(result) == 1 and result[0].startswith("/"):
            #     result = result
        else:
            return False

    def download_files(self, host_name, files):
        """"""
        tar_name = self.tar_files(host_name, files)
        down_filename = self.download(host_name, tar_name)
        logger.info(down_filename)
        self.rm_tarfile(host_name, tar_name)
        return down_filename


if __name__ == '__main__':
    class FlaskContext(object):

        def __init__(self):
            from application import Application

            self.application = Application()
            self.application.start()

            self.app_context = None

        def __enter__(self):
            self.app_context = self.application.app.app_context()
            self.app_context.push()

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.app_context.pop()


    with FlaskContext():
        download_files = [
            {
                "date": "2021-01-15",
                "name": "10.0.0.11",
                "path": r"Users\Administrator\Desktop\111"
            }
        ]
        sd = SaltAPI()
        print(sd.repeat_upload_content("10.0.0.11", "/root/app.py", "print.py"))
