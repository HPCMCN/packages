# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/2/1 15:38
# file: 04-数据缓存.py
# import os
#
# import django
#
# # set the default Django settings module for the 'celery' program.
# os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cmdb.settings.local")
# django.setup()

import time
import json
import logging
import contextlib
from hashlib import md5
from functools import wraps
from datetime import datetime
from multiprocessing import Manager

from django.conf import settings
from django_redis import get_redis_connection

logging = logging.root


class MemDB(object):

    def __init__(self):
        self.data = {}

    def get(self, key):
        res = self.data.get(key, None)
        if res and not (res.get("t") and res["s"] and time.time() - res["s"] > res["t"]):
            return res.get("r")
        self.delete(key)
        return None

    def set(self, key, result, t=None):
        res = {"s": time.time(), "t": t, "r": result}
        if t:
            res["s"] = time.time()
            res["t"] = t
        self.data[key] = res

    def delete(self, key):
        return self.data.pop(key, None)


mem = MemDB()


class Encoder(json.JSONEncoder):

    def encode(self, o):
        if isinstance(o, datetime):
            return o.strftime(settings.DATETIME_FORMAT)
        return super(Encoder, self).encode(o)


class CacheLock(object):

    def __init__(self, key, expire, db=None):
        self.cache_db = db
        self.key = key
        self.expire = expire
        self.lock_time = int(time.time())

    def __enter__(self):
        self.lock()
        return self

    def lock(self):
        st = int(self.cache_db.get(self.key) or 0)
        if st and not (self.expire and time.time() - st > self.expire):
            # 如果不是加锁时间过期, 都需要终止任务
            raise RuntimeError("任务执行已经执行, 无需重复!")
        logging.info(f"{self.lock_time}  任务执行加锁!")
        self.cache_db.set(self.key, self.lock_time)

    def release(self):
        if self.lock_time == int(self.cache_db.get(self.key) or 0):
            logging.info(f"{self.lock_time}  执行完成后释放锁!")
            self.cache_db.delete(self.key)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


# noinspection PyMethodMayBeStatic
class BaseCache(object):
    cache_prefix_field = "cache"
    lock_prefix_field = "lock"
    cache_db = mem

    def cache(self, t=0, lock=False, lock_time=None, cache_db=get_redis_connection):
        self.cache_db = cache_db or self.cache_db or get_redis_connection()

        def value(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                keys = self.get_keys(func, *args, **kwargs)
                with lock and CacheLock(keys["lock_key"], lock_time, self.cache_db) or contextlib.suppress():
                    return self.cache_call(keys["cache_key"], t, func, *args, **kwargs)

            return wrapper

        return value

    def cache_call(self, cache_key, t, func, *args, **kwargs):
        force = kwargs.pop("force", False)
        res = json.loads(self.cache_db.get(cache_key) or "{}")
        if force or not res:
            res = self.call_func(cache_key, t, func, *args, **kwargs)
        return res["result"]

    def call_func(self, cache_key, t, func, *args, **kwargs):
        result = {"result": func(*args, **kwargs)}
        result = json.dumps(result, cls=Encoder)
        self.cache_db.set(cache_key, result, t)
        return json.loads(result)

    def get_sign(self, func, *args, **kwargs):
        return func.__name__ + "-" + md5((str(args) + str(sorted(kwargs.items()))).encode()).hexdigest()

    def get_keys(self, func, *args, **kwargs):
        name = self.get_sign(func, *args, **kwargs)
        cache_name = f"{self.cache_prefix_field}-{name}"
        lock_name = f"{self.lock_prefix_field}-{name}"
        return {"cache_key": cache_name, "lock_key": lock_name}


class NameCache(BaseCache):

    def get_sign(self, func, *args, **kwargs):
        return func.__name__


# noinspection SpellCheckingInspection
def fparam(t=None, lock=True, lock_time=3, cache_db=None):
    """
    依照 函数传入的参数缓存
    缓存方案:
        1. 根据传入参数的md5, 进行缓存
        2. 当t=None时表示无限缓存, lock=True是否对本次参数提交进行加锁处理, 防止重复提交, lock_time超过时间限制则忽略该锁,
            被锁定时, 程序直接返回不会向下执行
        3. 调用被装饰函数时, 会增加一个force关键字参数, 此参数用于临时取消缓存, 注意此参数不会跳过lock和lock_time限制
    被函数输出数据尽量为内置类型: dict/bool/set/list...
    否则请完善: Encoder
    @cache.param(t=3600, lock=True)
    def test():
        pass

    test(force=True)  # 不再缓存
    :param t seconds 缓存时长
    :param lock bool 是否允许相同的数据重复提交, True表示加锁处理, 不提交重复数据
    :param lock_time seconds 重复数据允许提交的最小时间间隔, 使用此字段时, lock=True
    :param cache_db 缓存数据位置, 该对象必须有get/set/delete方法
    """
    return BaseCache().cache(t, lock, lock_time, cache_db)


# noinspection SpellCheckingInspection
def fname(t=None, lock=True, lock_time=3, cache_db=None):
    """以函数名为标识进行缓存"""
    return NameCache().cache(t, lock, lock_time, cache_db)


@fparam(t=5)
def param(a):
    import random
    i = random.randint(1, 100)
    print(f"a={a}, {i}")
    time.sleep(2)
    return i


@fname(t=5)
def name(a):
    import random
    i = random.randint(1, 100)
    print(f"a={a}, {i}")
    time.sleep(2)
    return i


if __name__ == '__main__':
    import threading
    t1 = threading.Thread(target=name, args=(1,))
    t2 = threading.Thread(target=name, args=(1,))
    t3 = threading.Thread(target=name, args=(2,))
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
