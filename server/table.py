from peewee import *
from flask_login import UserMixin

db = MySQLDatabase("auth-test", host="localhost", port=3306, user="shun", passwd="monke123")

class UserInfo(Model, UserMixin):
  id = AutoField()
  username = CharField()
  password = CharField()

  class Meta:
    database = db
    db_table="user_info"