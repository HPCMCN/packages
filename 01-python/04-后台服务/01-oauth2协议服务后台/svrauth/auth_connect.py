# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/1/11 9:25
# file: auth_connect.py
import time
import urllib.parse

import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


class Oauth2Req(object):

    def __init__(self):
        self.oauth_site = "http://127.0.0.1:8000/"
        self.client_id = "UPHLWpaC4dYn31R1mCGI3GuFVhyGeg8yd5verM0M"
        self.client_secret = "HIFKpn4xDklni6Ajeby9UgRlsKHbGcBCXNbtZjWtBKeaFSkGJ9MkgSWUg4cf4HLg7zAcxnZxDwXGjgn1NJ4qJmtflxSdC7D9gKjFD6kEYP7wh4s1nKS4uEOh6AU5AO0u"
        self.grant_type = "authorization_code"
        # 用户登录 oauth2 server 成功后, 需要回调 web 的地址
        self.redirect_uri = "http://127.0.0.1:7000/api/auth/daqun/login/callback/"
        self.auth_url = urllib.parse.urljoin(self.oauth_site, "/o/authorize/")
        self.token_url = urllib.parse.urljoin(self.oauth_site, "/o/token/")
        self.test_url = urllib.parse.urljoin(self.oauth_site, "/o/applications/")

    def oauth2_login_code(self):
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri
        }
        login_url = self.auth_url + "?" + urllib.parse.urlencode(params)
        print(login_url)
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
        try:
            driver.get(login_url)
        except:
            print("当且页面无法打开, 请确认后台是否正常!")
        while True:
            if self.redirect_uri in driver.current_url:
                break
            time.sleep(0.5)
        callback_uri = driver.current_url
        driver.close()
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(callback_uri).query))
        code = params.get("code")
        if not code:
            raise EnvironmentError("配置可能存在问题, 未获取到令牌code")
        print(f"当前code: {code}")
        return code

    def get_access_data(self, code):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": self.grant_type
        }
        print(data)
        return requests.post(
            self.token_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data
        ).json()

    def test_list_application(self, headers):
        print(requests.get(self.test_url, headers=headers).content)

    def start(self):
        """启动中心"""
        code = self.oauth2_login_code()
        # code = "XYzI6AFa1jaRXnVokV37IoJjRtLtB8"
        json_data = self.get_access_data(code)
        headers = {
            "Authorization": f"{json_data['token_type']} {json_data['access_token']}"
        }
        # 获取到token后, 即可查询对应接口信息, 比如 users(用户信息)/role(角色信息)/refresh_token(更新access_token)/login out(退出登陆)/reset password(重置密码)等等.
        self.test_list_application(headers)


if __name__ == '__main__':
    o = Oauth2Req()
    o.start()
