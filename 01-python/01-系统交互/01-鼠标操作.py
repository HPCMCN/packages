# -*- coding:utf-8 -*-
# author: HPCM
# time: 2022/12/30 22:51
# file: 01-鼠标操作.py
import time
from ctypes import windll, cdll, Structure, c_long, byref


class Mouse(object):
    """鼠标控制"""
    LEFT_KEY_DOWN = 2
    LEFT_KEY_UP = 4
    RIGHT_KEY_DOWN = 8
    RIGHT_KEY_UP = 16
    MID_KEY_DOWN = 32
    MID_KEY_UP = 64

    @staticmethod
    def create_point():
        """
        create point
        :return: point object
        """

        class Point(Structure):
            _fields_ = [("x", c_long), ("y", c_long)]

        return Point()

    @property
    def position(self):
        """
        get mouse position
        :return: (float, float)
        """
        pos = self.create_point()
        windll.user32.GetCursorPos(byref(pos))
        return pos.x, pos.y

    @classmethod
    def set_position(cls, x, y):
        """
        set mouse position
        :param x: float, x posistion
        :param y: float, y posistion
        """
        windll.user32.SetCursorPos(x, y)

    def left_click_down(self):
        """
        left click down
        :return:
        """
        windll.user32.mouse_event(self.LEFT_KEY_DOWN, 0, 0, 0)

    def left_click_up(self):
        """
        left click up
        :return:
        """
        windll.user32.mouse_event(self.LEFT_KEY_UP, 0, 0, 0)

    def left_click(self, n=1):
        """
        left click
        :param n: int, click number
        """
        for _ in range(n):
            self.left_click_down()
            time.sleep(0.1)
            self.left_click_up()

    def left_move_click(self, src, dst):
        """
        mouse click and move
        :param src: tuple, src position
        :param dst: tuple, dst position
        :return:
        """
        self.set_position(*src)
        self.left_click_down()
        time.sleep(0.1)
        self.set_position(*dst)
        self.left_click_up()

    def right_click_down(self):
        """
        click and move mouse
        :return:
        """
        windll.user32.mouse_event(self.RIGHT_KEY_DOWN, 0, 0, 0)

    def right_click_up(self):
        """
        click and move mouse
        :return:
        """
        windll.user32.mouse_event(self.RIGHT_KEY_UP, 0, 0, 0)

    def right_click(self, n=1):
        """
        right click
        :param n: int, click number
        """
        for _ in range(n):
            self.right_click_down()
            time.sleep(0.1)
            self.right_click_up()

    def mid_click_down(self):
        """
        click and move mouse
        :return:
        """
        windll.user32.mouse_event(self.MID_KEY_DOWN, 0, 0, 0)

    def mid_click_up(self):
        """
        click and move mouse
        :return:
        """
        windll.user32.mouse_event(self.MID_KEY_UP, 0, 0, 0)

    def mid_click(self, n=1):
        """
        middleware click
        :param n: int, click number
        """
        for _ in range(n):
            self.mid_click_down()
            time.sleep(0.1)
            self.mid_click_up()


if __name__ == '__main__':
    m = Mouse()
    print(m.position)
    m.set_position(333, 444)
    m.left_move_click((333, 444), (666, 444))