# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/1/12 16:05
# file: reproxy.py
"""
1. 阿里云申请一台按需收费的ECS
2. 将指定端口映射到该ECS上, 让其他机器可以访问到内网的机器
"""
import re
import os
import sys
import time
import argparse
import telnetlib
import subprocess
import logging.config
from multiprocessing import Process, freeze_support

import environ
import psutil
import pymysql
import paramiko
from alibabacloud_ecs20140526.client import Client as Ecs20140526Client
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_ecs20140526 import models as ecs_20140526_models

env = environ.Env()
env.read_env(open(".env", encoding="utf-8"))
pwd = env.str("password")
lp = env.int("local_port")
rp = env.int("remote_port")

logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "verbose": {
                "format": "[%(levelname).4s] %(asctime)s P_%(process)d_T_%(thread)d " +
                          "<%(module)s:%(lineno)d>: %(message)s"
            },
            "simple": {
                "format": "[%(levelname).4s] %(asctime)s P_%(process)d_T_%(thread)d " +
                          "<%(module)s:%(lineno)d>: %(message)s"
            }
        },
        "handlers": {
            "console": {
                "level": "DEBUG",
                "stream": "ext://sys.stdout",
                "class": "logging.StreamHandler",
                "formatter": "simple"
            }
        },
        "loggers": {
            "root": {
                "level": "INFO",
                "handlers": [
                    "console"
                ],
                "propagate": True
            }
        }
    }
)


class ECSInstance(object):
    """ECS实例的基本信息"""

    def __init__(self, detail):
        self._detail = detail

        self._host = None
        self._instance_id = None
        self.username = "root"
        self.port = 22

    @property
    def host(self):
        if self._host is None:
            addresses = self._detail.get("PublicIpAddress", {}).get("IpAddress", [])
            if not addresses:
                raise ValueError("当前主机的公网ip没有找到")
            self._host = addresses[0]
        return self._host

    @property
    def instance_id(self):
        if self._instance_id is None:
            instance_id = self._detail.get("InstanceId")
            if not instance_id:
                raise ValueError("当前主机的公网ip没有找到")
            self._instance_id = instance_id
        return self._instance_id


class ECSManger(object):
    """ECS管理"""

    def __init__(self, ak=None, sk=None, name=None, password=None, bandwidth=None, ignore_error=True):
        self.access_key = ak or env.str("access_key")
        self.secret_key = sk or env.str("secret_key")

        self.ignore_error = ignore_error
        self.bandwidth = bandwidth or env.int("bandwidth")  # 带宽
        self.ecs_name = name or env.str("ecs_name")  # 生成实例名称
        self.password = password or pwd  # 实例密码
        self.security_group = env.str("security_group")  # 安全组
        self.v_switch = env.str("v_switch")  # 交换机
        self.region = env.str("region")  # 地域

        self.play_type = "PostPaid"  # 按量付费
        self.ecs_type = "ecs.s6-c1m2.large"  # 2c4m
        self.os_image = "centos_7_9_x64_20G_alibase_20221129.vhd"  # centos 7.9镜像

        self._instance = None

    @property
    def instance(self):
        """aliyun指定name的ECS基本信息"""
        if self._instance is None:
            d = self.detail
            if not d:
                raise ValueError("实例ECS不存在!")
            self._instance = ECSInstance(d)
        return self._instance

    @property
    def client(self):
        config = open_api_models.Config(
            access_key_id=self.access_key,
            access_key_secret=self.secret_key
        )
        # 访问的域名
        config.endpoint = f'ecs-{self.region}.aliyuncs.com'
        return Ecs20140526Client(config)

    @property
    def detail(self):
        """详情信息"""
        logging.info(f"正在查询主机: {self.ecs_name}")
        describe_instances_request = ecs_20140526_models.DescribeInstancesRequest(
            region_id=self.region,
            instance_name=self.ecs_name
        )
        res = self.client.describe_instances(describe_instances_request).to_map()["body"]
        logging.info(f"当前获取信息: {res}")
        if res.get("TotalCount") != 1:
            return {}
        logging.info("查询成功: {} 个".format(len(res["Instances"]["Instance"])))
        return res["Instances"]["Instance"][0]

    @property
    def template_create(self):
        """aliyun按量计费ECS创建时, 的模板"""
        return {
            "region_id": self.region,
            "instance_type": self.ecs_type,
            "instance_name": self.ecs_name,
            "description": 'Remote connect',
            "instance_charge_type": self.play_type,
            "image_id": self.os_image,
            "internet_max_bandwidth_out": self.bandwidth,
            "amount": 1,
            "host_name": self.ecs_name,
            "password": self.password,
            "security_group_id": self.security_group,
            "v_switch_id": self.v_switch
        }

    def create(self):
        """创建ECS"""
        logging.info(f"开始创建主机: {self.ecs_name}")
        if self.detail:
            if self.ignore_error:
                logging.info("当前实例已存在, 直接开始使用!")
                return
            exit("当前名字的ECS已存在, 请勿重复创建")
        print(self.template_create)
        run_instances_request = ecs_20140526_models.RunInstancesRequest(**self.template_create)
        res = self.client.run_instances(run_instances_request).to_map()
        print("创建结果: ", res)
        if not res.get("statusCode") == 200:
            exit("创建失败!")
        ins_id = res.get("body", {}).get("InstanceIdSets", {}).get("InstanceIdSet", [])[0]
        while True:
            logging.info(f"正在检测实例是否初始化!")
            try:
                print(self.instance.host)
                break
            except:
                pass
            time.sleep(5)
        logging.info(f"当前实例id: {ins_id}")
        while not ReverseProxy.telnet(self.instance.host, self.instance.port):
            logging.info(f"正在检测实例时候可用!")
            time.sleep(5)
        logging.info(f"{self.instance.host}:{self.instance.port} 已就绪!")

    def start(self):
        """启动"""
        logging.info(f"执行开机命令: {self.ecs_name}")
        start_instance_request = ecs_20140526_models.StartInstanceRequest(
            instance_id=self.instance.instance_id
        )
        res = self.client.start_instance(start_instance_request).to_map()
        print("启动结果: ", res)
        status = res.get("statusCode") == 200
        logging.info(f"开机结果: {status}")

    def shutdown(self):
        """关机"""
        logging.info(f"关机实例: {self.ecs_name}")
        stop_instance_request = ecs_20140526_models.StopInstanceRequest(
            instance_id=self.instance.instance_id
        )
        status = self.client.stop_instance(stop_instance_request).to_map().get("statusCode") == 200
        logging.info(f"关机结果: {status}")
        return status

    def destroy(self):
        """销毁"""
        logging.info(f"销毁实例: {self.ecs_name}")
        delete_instance_request = ecs_20140526_models.DeleteInstanceRequest(
            instance_id=self.instance.instance_id,
            force=True
        )
        status = self.client.delete_instance(delete_instance_request).to_map()["statusCode"] == 200
        logging.info(f"销毁结果: {status}")


class ReverseProxy(object):
    """反向代理操作"""

    def __init__(self, host, port=None, username=None, password=None):
        self.private_key_path = env.str("private_key_path")
        self.public_key_path = env.str("public_key_path")
        self.ssh = None
        self.host = host
        self.port = port or env.int("port")
        self.username = username or env.str("username")
        self.password = password or pwd
        self.remote_authorized_keys = "~/.ssh/authorized_keys"
        self.remote_sshd_config = "/etc/ssh/sshd_config"

        self._ssh_path = None

    @staticmethod
    def telnet(host, port, timeout=1):
        """
        telnet命令, 测试端口是否连通
        :param host: str, 被测试host
        :param port: int, 被测试port
        :param timeout: int, 超时时间
        :return: bool
        """
        try:
            telnetlib.Telnet(host, port, timeout=timeout)
            return True
        except:
            return False

    def open_gateway(self):
        """开启sshd GatewayPorts"""
        self.rsa_login()
        gateway_configs = [
            "GatewayPorts yes",
            "ClientAliveInterval 60",
            "ClientAliveCountMax 3"
        ]
        is_change = False
        for gp in gateway_configs:
            try:
                if not self.has_gateway(gp):
                    is_change = True
                    logging.info("开启sshd的GatewayPorts")
                    self.ssh.exec_command(f"echo '{gp}' >> {self.remote_sshd_config}")
                    if not self.has_gateway(gp):
                        raise PermissionError(f"{gp} 配置失败!")
                    logging.info(f"sshd的{gp}已开启!")
            except Exception as e:
                logging.exception(e)
        if is_change:
            logging.info("重启sshd服务")
            try:
                stdin, stdout, stderr = self.ssh.exec_command(f"systemctl restart sshd && echo 111")
                if not stdout.read():
                    raise PermissionError("服务重启失败")
                logging.info("重启成功!")
            except Exception as e:
                logging.exception(e)
        time.sleep(2)
        self.ssh.close()

    def has_gateway(self, gp):
        """
        检查是否开启 GatewayPorts
        :param gp: str, 需要修改的config信息
        :return: bool
        """
        gp = gp.replace(" ", "\\ ")
        stdin, stdout, stderr = self.ssh.exec_command(f"grep '{gp}' {self.remote_sshd_config}")
        return bool(stdout.read())

    def has_rsa_public(self, user):
        """
        检查是否存在ssh public key
        :param user: str, rsa中的用户信息
        :return: bool
        """
        stdin, stdout, stderr = self.ssh.exec_command(f"grep '{user}' {self.remote_authorized_keys}")
        return bool(stdout.read())

    def password_login(self):
        """密码登录"""
        try:
            self.ssh.close()
        except:
            pass
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(self.host, self.port, self.username, self.password)

    def rsa_login(self):
        """rsa用户登录"""
        try:
            self.ssh.close()
        except:
            pass
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key_file(self.private_key_path)
        self.ssh.connect(self.host, self.port, self.username, pkey=private_key)

    def reset_rsa_fingerprint(self):
        """清理指纹"""
        obs_path = os.path.join(".ssh", "known_hosts")
        base_path = env.str("HOMEDRIVE") + env.str("HOMEPATH")
        fp_file = os.path.join(base_path, obs_path)

        fp_contents = []
        with open(fp_file, "r") as fp:
            for x in fp:
                if self.host not in x:
                    fp_contents.append(x)
        with open(fp_file, "w+") as fp:
            fp.write("".join(fp_contents))

    def set_rsa_key(self):
        """配置秘钥登录"""
        self.password_login()
        with open(self.public_key_path) as fp:
            public_key = fp.read()
        user = public_key.split()[-1]
        try:
            if not self.has_rsa_public(user):
                logging.info("开始配置密钥对!")
                self.ssh.exec_command(f"echo '{public_key}' >> {self.remote_authorized_keys}")
                if not self.has_rsa_public(user):
                    raise PermissionError("秘钥设置失败!")
        except:
            self.ssh.close()
            raise PermissionError("秘钥设置失败!")
        logging.info("秘钥对配置成功!")

    def find_ssh_path_win(self):
        """在window系统中寻找ssh绝对路径"""
        if self._ssh_path is None:
            logging.info("检测ssh所在位置")
            process = subprocess.Popen(f"where ssh", shell=True, stdout=subprocess.PIPE)
            path = process.stdout.read().decode().strip()
            if os.sep in path:
                self._ssh_path = path
            else:
                logging.info(f"开始扫描整个系统的环境变量")
                paths = set()
                for s in os.environ.values():
                    if os.sep not in s:
                        continue
                    if ";" in s:
                        [paths.add(x.strip()) for x in s.split(";") if x.strip()]
                    else:
                        paths.add(s)
                for s in paths:
                    try:
                        if "ssh.exe" in str(os.listdir(s)):
                            self._ssh_path = os.path.join(s, "ssh.exe")
                            break
                    except:
                        pass
                else:
                    raise EnvironmentError("未在 系统环境 环境变量 中寻找到 ssh.exe程序, 请配置后重试!")
        logging.info(f"已找到: {self._ssh_path}")
        return self._ssh_path

    def win_reverse_proxy(self, local, remote):
        """建立反向代理 windows
        将本机端口映射到公网机器中的一个端口上面, 让外网可以访问到
        :param local: int, 本机需要反向代理的端口
        :param remote: int, 远端转发端口
        """
        ssh_path = self.find_ssh_path_win()
        logging.info(f"正在开始端口转发: {remote} ==> {local}")
        cmd = f"{ssh_path} -o StrictHostKeyChecking=no -o TCPKeepAlive=yes -o ServerAliveInterval=30 " + \
              f"-N -f -R {remote}:localhost:{local} {self.username}@{self.host} -i {self.private_key_path}"
        logging.info(cmd)
        os.system(cmd)
        logging.info(f"操作完成: {remote} ==> {local}")

    def linux_reverse_proxy(self, local, remote):
        """建立反向代理 linux
        将本机端口映射到公网机器中的一个端口上面, 让外网可以访问到
        :param local: int, 本机需要反向代理的端口
        :param remote: int, 远端转发端口
        """
        cmd = "ssh"
        logging.info(f"正在开始端口转发: {remote} ==> {local}")
        os.system(f"{cmd} -o StrictHostKeyChecking=no -o TCPKeepAlive=yes -o ServerAliveInterval=30 " +
                  f"-NfR {remote}:localhost:{local} {self.username}@{self.host} -i {self.private_key_path}")
        logging.info(cmd)
        os.system(cmd)
        logging.info(f"操作完成: {remote} ==> {local}")

    def reverse_proxy(self, local=22, remote=4122):
        """反向代理
        将本机端口映射到公网机器中的一个端口上面, 让外网可以访问到
        :param local: int, 本机需要反向代理的端口
        :param remote: int, 远端转发端口
        """
        self.reset_rsa_fingerprint()
        self.clean_proxy(local, remote)
        if sys.platform.startswith("win"):
            self.win_reverse_proxy(local, remote)
        else:
            self.linux_reverse_proxy(local, remote)

    def check_proxy(self, local, remote, t):
        """
        检查代理端口是否连通
        :param local: int, 本地端口
        :param remote: int, map端口
        :param t: float, 检查间隔时间
        :return:
        """
        logging.info("监听代理已启动")
        p = None
        while True:
            if not p or not self.telnet(self.host, remote) and self.telnet(self.host, 22):
                logging.info("代理端口出现问题, 正在重试!")
                p and p.kill()
                p = Process(target=self.reverse_proxy, args=(local, remote))
                p.start()
            else:
                logging.info("端口检测正常!")
            time.sleep(t)

    def remote_clean_proxy(self, port):
        """
        清理代理信息
        :param port: int, 被清理端口. 如果不填写, 则清理所有
        :return:
        """
        if port is not None:
            kill_cmd = "netstat -nlp | grep -o '%d .*/sshd' | awk -F'[ /]' '{print $(NF-1)}' | xargs kill -9" % port
        else:
            kill_cmd = "netstat -nlp | grep -Po '\\d+/sshd:' | awk -F'[ /]' '{print $(NF-1)}' | xargs kill -9"
        self.rsa_login()
        self.ssh.exec_command(kill_cmd)
        logging.info("已经清理完成!")

    def remote_proxy_pids(self, port):
        """
        清理代理信息
        :param port: int, 被清理端口. 如果不填写, 则清理所有
        :return: list[pid1, pid2 ..]
        """
        if port is not None:
            pid_cmd = "netstat -nlp | grep -o '%d .*/sshd' | awk -F'[ /]' '{print $(NF-1)}'" % port
        else:
            pid_cmd = "netstat -nlp | grep -Po '\\d+/sshd:' | awk -F'[ /]' '{print $(NF-1)}'"
        self.rsa_login()
        stdin, stdout, stderr = self.ssh.exec_command(pid_cmd)
        pid = [x for x in stderr.read().split() if x.strip()]
        return pid

    def proxy_process(self, local_port, remote_port):
        """
        获取本机的proxy进程
        :param local_port: 本地端口
        :param remote_port: 远程端口
        :return: list[process1, process2...]
        """
        name = "ssh.exe" if sys.platform.startswith("win") else "ssh"
        if local_port is None and remote_port is None:
            reg = r"\d+?:localhost:\d+?.*%s" % self.host
        else:
            reg = r"%s:localhost:%s.*%s" % (remote_port, local_port, self.host)
        processes = []
        for proc in psutil.process_iter(["pid", "name", "cmdline", "cwd", "environ"]):
            if proc.name() == name and re.findall(reg, "".join(proc.cmdline())):
                processes.append(proc)
        return processes

    def local_clean_proxy(self, local_port, remote_port):
        """
        清理代理信息
        :param local_port: 本地端口
        :param remote_port: 远程端口
        :return:
        """
        processes = self.proxy_process(local_port, remote_port)
        if processes:
            logging.info("发现进程: {} 个, 准备开始清理".format(len(processes)))
            for proc in processes:
                proc.kill()
                logging.info(f"已清理: {proc.name()} ==> {proc.pid}")
            logging.info("已清理完成")
        else:
            logging.info("未发现本机代理程序!")

    def clean_proxy(self, local_port, remote_port):
        """
        清理代理信息
        :param local_port: 本地端口
        :param remote_port: 远程端口
        :return
        """
        logging.info("开始清理本地代理")
        self.local_clean_proxy(local_port, remote_port)
        logging.info("开始清理服务器代理")
        self.remote_clean_proxy(remote_port)

    def proxy_status(self, local_port, remote_port):
        """
        获取代理状态
        :param local_port: 本地端口
        :param remote_port: 远程端口
        :return: bool
        """
        if not self.telnet(self.host, remote_port):
            if bool(self.remote_proxy_pids(remote_port)):
                logging.warning("远程代理被占用")
                return True
            if bool(self.proxy_process(local_port, remote_port)):
                logging.warning("本地服务已经启动!")
                return True
            return False
        return True

    def loop_reverse_proxy(self, local=22, remote=4122, t=60):
        """循环监听反向代理
        将本机端口映射到公网机器中的一个端口上面, 让外网可以访问到
        :param local: int, 本机需要反向代理的端口
        :param remote: int, 远端转发端口
        :param t: int, 监听时间, 如果出现无法访问情况将强制重启
        :return
        """
        self.set_rsa_key()
        time.sleep(2)
        self.open_gateway()
        self.check_proxy(local, remote, t)

    @classmethod
    def get_action(cls, host=None, port=None, user=None, password=None, db_name=None):
        """
        从数据库获取到操作状态
        :param host: str, mysql host
        :param port: int, mysql port
        :param user: str, mysql user
        :param password: str, mysql password
        :param db_name: str, mysql database
        :return:
        """
        pyobj = pymysql.connect(
            host=host or env.str("mysql_host"),
            port=port or env.int("mysql_port"),
            user=user or env.str("mysql_user"),
            password=password or env.str("mysql_password"),
            db=db_name or env.str("mysql_db_name")
        )
        cur = pyobj.cursor()
        try:
            cur.execute("select value from tb_actions where id=1")
            res = cur.fetchall()
        finally:
            cur.close()
            pyobj.close()
        if res:
            return res[0][0]


class ShellManager(object):
    """命令行管理"""

    def __init__(self):
        self.parser = argparse.ArgumentParser(description="""
常用命令: 
    1. aliyun ECS采购 + 开通反向代理:
        reproxy.exe -ak 阿里云acces_key -sk 阿里云secret_key -n ecs-mapping-name -p 服务器密码(自己设置) -c -mp 服务器需要代理的端口 -lp 内网需要暴露的端口
        示例:
            reproxy.exe -ak LT***r -sk TN***p -n ecs-mapping-name -p W***b -c -mp 4389 -lp 3389
    2. aliyun ECS 信息查看
        示例:
            reproxy.exe -ak LT***r -sk TN***p -n ecs-mapping-name -p W***b -s
    3. aliyun ECS清理反向代理
        示例:
            reproxy.exe -ak LT***r -sk TN***p -n ecs-mapping-name -p W***b -s -r
    4. 销毁实例
        示例:
            reproxy.exe -ak LT***r -sk TN***p -n ecs-mapping-name -d
    5. 自建服务器开通反向代理
        示例:
            reproxy.exe -H 47.**.83 -p W***b -mp 4389 -lp 3389
    6. 自建服务器清理反向代理
        示例:
            reproxy.exe -H 47.**.83 -p W***b -r
""")

    def parser_reverse_proxy(self):
        """反向代理参数"""
        parser = self.parser.add_argument_group(
            "proxy",
            description="代理信息配置, 注意阿里云里面的费用一定要大于100元, 否则无法调用!")
        parser.add_argument("-mp", "--mapping-port", type=int, help="被映射的端口")
        parser.add_argument("-lp", "--local-port", type=int, help="本地需要外放的端口")
        parser.add_argument("-H", "--host", help="服务器地址")
        parser.add_argument("-u", "--username", default="root", help="服务器账号")
        parser.add_argument("-p", "--password", help="服务器密码")
        parser.add_argument("-P", "--port", default=22, type=int, help="服务器账号")
        parser.add_argument("-r", "--reset", nargs="?", const=-1, default=None, type=int, help="清理代理端口")

    def parser_ecs(self):
        """ecs管理参数"""
        parser = self.parser.add_argument_group("aly", description="aliyun 操作配置")
        parser.add_argument("-ak", "--access-key", help="阿里云平台的access_key")
        parser.add_argument("-sk", "--secret-key", help="阿里云平台的secret_key")
        parser.add_argument("-n", "--name", help="ECS的名称")
        parser.add_argument("-b", "--bandwidth", type=int, default=10, help="ECS带宽")
        mult_parser = parser.add_mutually_exclusive_group()
        mult_parser.add_argument("-c", "--create", action="store_true", help="创建ECS")
        mult_parser.add_argument("-s", "--select", action="store_true", help="查询ECS")
        mult_parser.add_argument("-d", "--destroy", action="store_true", help="销毁ECS")

    def select_ecs(self, ak, sk, name):
        print(f"查询: ", ak, sk, name)
        em = ECSManger(ak, sk, name)
        host_port = em.instance.host, em.instance.port
        print(f"当前主机: {host_port}")
        return host_port

    def create_ecs(self, ak, sk, name, password, bandwidth):
        print(f"创建: ", ak, sk, name, password, bandwidth)
        em = ECSManger(ak, sk, name, password, bandwidth)
        em.create()
        host_port = em.instance.host, em.instance.port
        print(f"当前主机: {host_port}")
        return host_port

    def destroy(self, ak, sk, name):
        print(f"销毁: ", ak, sk, name)
        em = ECSManger(ak, sk, name)
        em.destroy()

    def reverse_proxy(self, host, port, username, password, remote_port, local_port):
        print("正在设置反向代理: ", host, port, username, password, remote_port, local_port)
        sr = ReverseProxy(host, port, username, password)
        sr.loop_reverse_proxy(local_port, remote_port)

    def clean_proxy(self, host, port, username, password, local_port, remote_port):
        print("正在重置代理: ", host, port, username, password)
        sr = ReverseProxy(host, port, username, password)
        sr.clean_proxy(local_port, remote_port)

    def handler(self, data):
        ak, sk = data.access_key, data.secret_key
        host, port, username, password = data.host, data.port, data.username, data.password
        ecs_name, bandwidth = data.name, data.bandwidth
        mapping_port, local_port = data.mapping_port, data.local_port
        if any([data.create, data.destroy, data.select]):
            if not ecs_name:
                exit("Error: name must be set!")
            # do aliyun something
            if data.create:
                if not password:
                    exit("Error: password must be set!")
                host, port = self.create_ecs(ak, sk, ecs_name, password, bandwidth)
            elif data.select:
                host, port = self.select_ecs(ak, sk, ecs_name)
            else:
                self.destroy(ak, sk, ecs_name)
                exit(0)
        if any([mapping_port, local_port]) and not data.reset:
            print(host, port, username, password, mapping_port, local_port)
            if not all([host, port, username, password, mapping_port, local_port]):
                exit("Error: `host, port, username, password, mapping_port, local_port` must be set!")
            # proxy
            self.reverse_proxy(host, port, username, password, mapping_port, local_port)
        if data.reset:
            print("重置端口: ", host, port, username, password, data.reset)
            if not all([host, port, username, password, mapping_port, local_port]):
                exit("Error: `host, port, username, password, mapping_port, local_port` must be set!")
            self.clean_proxy(host, port, username, password, local_port, mapping_port)

    def start(self):
        self.parser_ecs()
        self.parser_reverse_proxy()
        data = self.parser.parse_args()
        self.handler(data)


class AppManager(object):

    def __init__(self):
        self.host = None
        self.port = None

    def proxy(self):
        em = ECSManger()
        em.create()
        host, port, username = em.instance.host, em.instance.port, em.instance.username

        rpx = ReverseProxy(host, port, username, pwd)
        rpx.loop_reverse_proxy(lp, rp)

    def destroy(self):
        em = ECSManger()
        if not em.detail:
            logging.info("未找到在使用的ECS!")
            return
        em.destroy()

    def sync_process(self):
        logging.info("开始创建reproxy")
        process = Process(target=self.proxy)
        process.start()
        return process

    def loop_check(self, t=10):
        process = None
        pre_state = None
        while True:
            state = ReverseProxy.get_action()
            logging.info(f"state: {state}")
            if pre_state == state:
                time.sleep(t)
                continue
            pre_state = state
            if state.startswith("start"):
                if process:
                    process.kill()
                process = self.sync_process()
            elif state == "restart":
                if process:
                    process.kill()
                process = self.sync_process()
            elif state == "destroy":
                if process:
                    process.kill()
                logging.info("清理并销毁ECS")
                self.destroy()
            else:
                logging.error("must set `start, start_force, restart,destroy`")
                time.sleep(5)
                continue
            time.sleep(t)


if __name__ == '__main__':
    freeze_support()
    am = ShellManager()
    am.start()
