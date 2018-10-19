#!/usr/bin/env.python
# -*- coding: utf-8 -*-

from aliyunsdkdysmsapi.request.v20170525 import SendSmsRequest
from aliyunsdkdysmsapi.request.v20170525 import QuerySendDetailsRequest
from aliyunsdkcore.client import AcsClient
import hashlib
import psycopg2
import psycopg2.extras
import time
import datetime
from flask import Flask, request, jsonify,make_response
from system_conf import *
from functools import wraps
import random
import redis
from datetime import date
import json
import requests

class DataSwitch():
    '''
    数据交换
    '''

    def __init__(self, server, port, user, password, db_name, autocommit=False):
        self.conn = psycopg2.connect(host=server, port=port, user=user, password=password, database=db_name)
        self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        self.conn.autocommit = autocommit

    def __del__(self):
        if (self.cursor != None):
            self.cursor.close()

        if (self.conn != None):
            self.conn.close()

    def send_sms(business_id, phone_number, sign_name, template_code, template_param=None):
        REGION = SMS_REGION  # 暂时不支持多region
        ACCESS_KEY_ID = SMS_ACCESS_KEY_ID
        ACCESS_KEY_SECRET = SMS_ACCESS_KEY_SECRET
        acs_client = AcsClient(ACCESS_KEY_ID, ACCESS_KEY_SECRET, REGION)

        smsRequest = SendSmsRequest.SendSmsRequest()
        # 申请的短信模板编码,必填
        smsRequest.set_TemplateCode(template_code)
        # 短信模板变量参数,友情提示:如果JSON中需要带换行符,请参照标准的JSON协议对换行符的要求,比如短信内容中包含\r\n的情况在JSON中需要表示成\\r\\n,否则会导致JSON在服务端解析失败
        if template_param is not None:
            smsRequest.set_TemplateParam(template_param)
        # 设置业务请求流水号，必填。
        smsRequest.set_OutId(business_id)
        # 短信签名
        smsRequest.set_SignName(sign_name);
        # 短信发送的号码，必填。支持以逗号分隔的形式进行批量调用，批量上限为1000个手机号码,批量调用相对于单条调用及时性稍有延迟,验证码类型的短信推荐使用单条调用的方式
        smsRequest.set_PhoneNumbers(phone_number)
        # 发送请求
        smsResponse = acs_client.do_action_with_exception(smsRequest)
        return smsResponse
    def insert_user_permissions(self, access_key,pid,cpl):
        '''
        修改权限
        '''
        try:
            sql1 = "SELECT uid FROM user_info WHERE access_key=%s"
            self.cursor.execute(sql1,(access_key,))
            uid = self.cursor.fetchone()[0]

            sql = "UPDATE product_info SET cpl=%s WHERE uid = %s AND pid=%s;"
            self.cursor.execute(sql, (cpl,uid,pid,))
            self.conn.commit();
        except Exception, e:
            self.conn.rollback();
            return False
    def insert_user_info(self, access_key,secret_key,username, password,phone,email,registerdate):
        '''
        插入用户信息
        '''
        try:
            sql1 = "SELECT max(uid) FROM user_info"
            self.cursor.execute(sql1)
            uid = self.cursor.fetchone()[0]
            if self.cursor.fetchone() == []:
                uid = 1
            else:
                uid += 1
            sql = "INSERT INTO user_info (uid,access_key,secret_key,username,password,mail,telephone,registerdate)VALUES(%s,%s,%s,%s,%s,%s,%s,%s)"
            self.cursor.execute(sql,(uid,access_key,secret_key,username, password,phone,email,registerdate))
            self.conn.commit();
        except Exception, e:
            self.conn.rollback();
            return False
        return True

    def insert_product_info(self,username,pid,cpl,authorizationdate,indate):
        '''
        插入用户产品权限信息
        '''
        try:
            sql1 = "SELECT max(id) FROM product_info"
            self.cursor.execute(sql1)
            id = self.cursor.fetchone()[0]
            if self.cursor.fetchone() == []:
                id = 1
            else:
                id += 1

            handle = DataSwitch(DB_HOSTNAME, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME)
            handle_get_uid = handle.get_uid(username)
            uid = handle_get_uid.values()[0]
            sql = "INSERT INTO product_info (id,uid,pid,cpl,authorizationdate,indate)VALUES(%s,%s,%s,%s,%s,%s)"
            self.cursor.execute(sql, (id,uid,pid,cpl,authorizationdate,indate))
            self.conn.commit();
        except Exception, e:
            print e
            self.conn.rollback();
            return False
        return True

    def get_uid(self,username):
        '''
        根据username获取用户uid
        '''
        sql = "SELECT * FROM user_info WHERE username =%s"
        self.cursor.execute(sql, (username,))
        dict_uid = self.cursor.fetchone()

        if dict_uid == None:
            return None

        dict_return = {}
        for ele in ["uid"]:
            if dict_uid.has_key(ele):

                if type(dict_uid[ele]) == datetime.date:
                    dict_uid[ele] = str(dict_uid[ele])

                dict_return[ele] = dict_uid[ele]
            else:
                dict_return[ele] = None
        return dict_return

    def get_user_info(self, user, passwd):
        '''
        获取用户信息
        返回值: 失败返回None, 成功返回字典型用户信息
        '''

        sql = "SELECT * FROM user_info WHERE username =%s AND password =%s"
        self.cursor.execute(sql, (user, passwd))
        dict_user_info = self.cursor.fetchone()

        if dict_user_info == None:
            return None

        dict_return = {}
        for ele in ["username", "access_key", "secret_key", "registerdate", "idcard"]:
            if dict_user_info.has_key(ele):

                if type(dict_user_info[ele]) == datetime.date:
                    dict_user_info[ele] = str(dict_user_info[ele])

                dict_return[ele] = dict_user_info[ele]
            else:
                dict_return[ele] = None
        return dict_return

    def get_secret_key(self, access_key):
        '''
        获取secret_key
        返回值: 失败返回None, 成功返回字典型secret_key
        '''

        sql = "SELECT * FROM user_info WHERE access_key =%s"
        self.cursor.execute(sql, (access_key,))
        dict_secret_key = self.cursor.fetchone()

        if dict_secret_key == None:
            return None

        dict_return = {}
        for ele in ["secret_key"]:
            if dict_secret_key.has_key(ele):

                if type(dict_secret_key[ele]) == datetime.date:
                    dict_secret_key[ele] = str(dict_secret_key[ele])

                dict_return[ele] = dict_secret_key[ele]
            else:
                dict_return[ele] = None
        return dict_return

    def get_access_key_cpl(self, access_key,pid):
        '''
        获取access_key权限等级，判断是否是产品权限
        返回值: 不是返回False, 是返回True
        '''

        sql = "SELECT cpl FROM product_info WHERE uid =(SELECT uid FROM user_info WHERE access_key =%s) AND pid=%s"
        self.cursor.execute(sql, (access_key,pid))
        dict_cpl = self.cursor.fetchone()
        if dict_cpl == [0]:
            return True
        return False

    def get_useraccess_key_cpl(self, useraccess_key,pid):
        '''
        获取useraccess_key权限等级，判断是否是产品权限
        返回值: 不是返回True, 是返回False
        '''

        sql = "SELECT cpl FROM product_info WHERE uid =(SELECT uid FROM user_info WHERE access_key =%s) AND pid=%s"
        self.cursor.execute(sql, (useraccess_key,pid))
        dict_cpl = self.cursor.fetchone()
        if dict_cpl == None:
            return False
        if dict_cpl != [0]:
            return True
        return False

    def get_cpl(self, useraccess_key,pid):
        '''
        获取权限等级,有效期过期，把权限等级置空
        返回值: 失败返回'time out', 成功返回字典型cpl
        '''

        sql = "SELECT cpl FROM product_info WHERE uid =(SELECT uid FROM user_info WHERE access_key =%s) AND pid=%s"
        self.cursor.execute(sql, (useraccess_key,pid))
        dict_cpl = self.cursor.fetchone()
        if dict_cpl == None:
            return None
        if dict_cpl == ['']:
            return 'time out'
        dict_return = {}
        for ele in ["cpl"]:
            if dict_cpl.has_key(ele):

                if type(dict_cpl[ele]) == datetime.date:
                    dict_cpl[ele] = str(dict_cpl[ele])

                dict_return[ele] = dict_cpl[ele]
            else:
                dict_return[ele] = None

        return dict_return

    def verify(self, access_key, timestamp, signature):
        '''
        函数功能: 通信加密验证
        输入参数: access_key,timestamp,signature
        返回值:   验证是否成功
        '''
        if abs(time.time() - float(timestamp)) > MAX_RESPONSE_TIME:
            return 'time out'

        handle = DataSwitch(DB_HOSTNAME, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME)
        dict_secret_key = handle.get_secret_key(access_key)
        if dict_secret_key == None:
            return None
        else:
            signature1 = hashlib.md5(str(timestamp) + str(dict_secret_key.values()[0])).hexdigest().lower()
            if signature == signature1:
                return True
            return ERROR_MSG_INVALID_SIGNATURE

__author__ = 'keeper_zdl'

app = Flask(__name__)

def allow_cross_domain(fun):
    @wraps(fun)
    def wrapper_fun(*args, **kwargs):
        rst = make_response(fun(*args, **kwargs))
        rst.headers['Access-Control-Allow-Origin'] = '*'
        rst.headers['Access-Control-Allow-Methods'] = 'PUT,GET,POST,DELETE'
        allow_headers = "Referer,Accept,Origin,User-Agent"
        rst.headers['Access-Control-Allow-Headers'] = allow_headers
        return rst
    return wrapper_fun

'''
    函数功能: 获取用户基本信息
    输入参数: username,password
    返回值:   用户基本信息
'''
@app.route('/login', methods=['POST'])
@allow_cross_domain
def login():
    try:
        username = request.form['username']
        password = request.form['password']
    except Exception, e:
        return jsonify(success=False, error=ERROR_MSG_MISS_PARAM)

    handle = DataSwitch(DB_HOSTNAME, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME)
    dict_user_info = handle.get_user_info(username, password)
    if dict_user_info == None:
        return jsonify(success=False, error=ERROR_MSG_INVALID_USER_PASSWD, username=username)

    return jsonify(success=True, error="", **dict_user_info)

'''
    函数功能: 获取用户secret_key和权限等级
    输入参数: access_key,timestamp,signature,pid，useraccess_key
    返回值  :secret_key,cpl，pid
'''

@app.route('/get_user_privilege', methods=['POST'])
@allow_cross_domain
def get_user_permission():
    try:
        access_key = request.form['access_key']
        timestamp = request.form['timestamp']
        signature = request.form['signature']
        useraccess_key = request.form['useraccess_key']
        pid = request.form['pid']
    except Exception, e:
        return jsonify(success=False, error=ERROR_MSG_MISS_PARAM)

    handle = DataSwitch(DB_HOSTNAME, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME)
    dict_verify = handle.verify(access_key,timestamp,signature)
    dict_get_secret_key = handle.get_secret_key(useraccess_key)
    dict_get_cpl = handle.get_cpl(useraccess_key,pid)
    dict_get_access_key_cpl = handle.get_access_key_cpl(access_key,pid)
    dict_get_useraccess_key_cpl = handle.get_useraccess_key_cpl(useraccess_key,pid)

    if dict_verify == 'time out':
        return jsonify(success=False, error=ERROR_MSG_INVALID_TIMESTAMP)
    if dict_verify == None:
        return jsonify(success=False, error=ERROR_MSG_INVALID_ACCESS_KEY)
    if dict_verify == 'Invalid signature':
        return jsonify(success=False, error=ERROR_MSG_INVALID_SIGNATURE)
    if dict_verify == True:#判断权限认证是否通过
        if dict_get_access_key_cpl == True:#判断access_key是否是产品权限
            if dict_get_useraccess_key_cpl == True:#判断useraccess_key是否是用户权限
                if dict_get_cpl == 'time out':
                    return jsonify(success=False, error=ERROR_MSG_INVALID_INDATE)
                dict_secret_key_cpl = dict(dict_get_secret_key, **dict_get_cpl)
                return jsonify(success=True,error='',pid=request.form['pid'],**dict_secret_key_cpl)
            return jsonify(success=False, error=ERROR_MSG_INVALID_USER_ACCESS_KEY)
        return jsonify(success=False,error=ERROR_MSG_INVALID_PRODUCT_ACCESS_KEY)

'''
    函数功能:给用户发送验证码
    输入参数:phone
    返回值  :success,error
'''

@app.route('/send_sms', methods=['POST'])
@allow_cross_domain
def send_sms():
    try:
        phone = request.form['phone']
    except Exception, e:
        return jsonify(success=False, error=ERROR_PHONE)

    handle = DataSwitch(DB_HOSTNAME, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME)
    code = random.randint(100000, 999999)
    # params = "{\"code\":\"code\",\"product\":\"TID\"}"
    params = {"code":code,"product":"TID"}
    handle.send_sms(phone,SMS_SIGN_NAME,SMS_TEMPLATE_CODE,params)

    pool = redis.ConnectionPool(host=REDIS_HOSTNAME, port=REDIS_PORT,password = REDIS_PASSWORD)
    r = redis.StrictRedis(connection_pool=pool)
    r.set(phone,code)
    r.expire(phone,CACHE_TIME)
    return jsonify(success=True, error='',phone=phone)

'''
    函数功能:注册
    输入参数:username,password,email,phone,code，pid
    返回值  :success,error
'''

@app.route('/register', methods=['POST'])
@allow_cross_domain
def register():
    try:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        code = request.form['code']
        pid = request.form['pid']
    except Exception, e:
        return jsonify(success=False, error=ERROR_MSG_MISS_PARAM)

    pool = redis.ConnectionPool(host=REDIS_HOSTNAME, port=REDIS_PORT,password = REDIS_PASSWORD)
    r = redis.StrictRedis(connection_pool=pool)
    code1 = r.get(phone)
    if str(code) == code1:
        if pid != TIA and pid != TID:
            return jsonify(success=False, error=ERROR_PID)
        access_key = hashlib.md5(username+password).hexdigest().lower()
        secret_key = hashlib.md5(access_key).hexdigest().lower()
        registerdate = date.today()
        cpl = -1
        authorizationdate = date.today()
        indate = date.today()
        handle = DataSwitch(DB_HOSTNAME, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME)
        handle_insert_user_info = handle.insert_user_info(access_key,secret_key,username, password,email,phone,registerdate)
        handle_insert_product_info = handle.insert_product_info(username,pid,cpl,authorizationdate,indate)

        if handle_insert_user_info == False:
            return jsonify(success=False, error=ERROR_USERNAME)
        if handle_insert_user_info == True:
            if handle_insert_product_info == True:
                return jsonify(success=True, error='')
            if handle_insert_product_info == False:
                return jsonify(success=False, error=ERROR_PID)
    return jsonify(success=False, error=ERROR_CODE)

'''
    函数功能:修改用户权限
    输入参数:access_key,pid,cpl
    返回值  :success,error
'''
@app.route('/permission', methods=['POST'])
@allow_cross_domain
def permission():
    try:
        access_key = request.form['access_key']
        pid = request.form['pid']
        cpl = request.form['cpl']
    except Exception, e:
        return jsonify(success=False, error=ERROR_MSG_MISS_PARAM)
    handle = DataSwitch(DB_HOSTNAME, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME)
    handle_user_permission = handle.insert_user_permissions(access_key,pid,cpl)

    if pid not in ['tid','tia']:
        return jsonify(success=False, error=ERROR_PID)
    if handle_user_permission == False:
        return jsonify(success=False, error=ERROR_MSG_INVALID_ACCESS_KEY)
    return jsonify(success=True, error='')

if __name__ == '__main__':
    app.debug = True
    app.run('0.0.0.0',80)