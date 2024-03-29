# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/2/1 14:51
# file: 01-斐波那契.py
# 1. 普通版

def list_feb(index):
    a, b, c = 0, 1, 1
    list_n = []
    while c < index:
        a, b = b, b + a
        list_n.append(b)
        c += 1
    return list_n


for i in list_feb(10000):
    print(i)


# 2. 递归

def recursive_feb(index):
    if index <= 2:
        return 1
    else:
        return recursive_feb(index - 1) + recursive_feb(index - 2)


print(recursive_feb(2))


# 3. 生成器

def generator_feb(index):
    a, b, c = 0, 1, 1
    yield b
    while c < index:
        a, b = b, b + a
        yield b
        c += 1
    raise StopIteration


for i in generator_feb(10000):
    print(i)


#######################################
def foo(nums):
    a, b = 0, 1
    for _ in range(nums):
        yield a
        a, b = b, a + b


print(list(foo(10)))
