# 1. 启动环境准备
* 删除db.sqlite3文件

  ```
  rm -f db.sqlite3
  ```

* 安装依赖

  ```
  pip install -r requirements.txt
  ```
* 重新迁移文件

  ```
  python manage.py migrate
  ```
* 启动服务

  ```
  python manage.py runserver
  ```
# 2. 授权三方网站访问 oauth2
* 创建可以登录的用户

  ```
  python manage.py createsuperuser
  ```
* 访问已经授权的application

  ```
  http://localhost:8000/o/applications/
  ```
* 为app授权

https://django-oauth-toolkit.readthedocs.io/en/1.7.1/getting_started.html#authorization-code

  