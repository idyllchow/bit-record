#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'url handlers'

import re, time, json, logging, hashlib, base64, asyncio

import markdown2

from aiohttp import web

from coroweb import get, post
from apis import Page, APIValueError, APIResourceNotFoundError, APIError

from models import User, Interface, next_id

from config import configs
import markdown2
logging.basicConfig(level=logging.DEBUG)

# email的匹配正则表达式
_RE_EMAIL = re.compile(     
    r'^[a-z0-9\.\-\_]+\@[a-z0-9\-\_]+(\.[a-z0-9\-\_]+){1,4}$')
# 密码的匹配正则表达式
_RE_SHA1 = re.compile(r'^[0-9a-f]{40}$')
     
COOKIE_NAME = 'awesession'
_COOKIE_KEY = configs.session.secret

def check_admin(request):
    if request.__user__ is None or not request.__user__.admin:
        raise APIPermissionError()

def get_page_index(page_str):
    p = 1
    try:
        p = int(page_str)
    except ValueError as e:
        pass
    if p < 1:
        p = 1
    return p

def user2cookie(user, max_age):
    '''
    Generate cookie str by user.
    '''
    # build cookie string by: id-expires-sha1
    expires = str(int(time.time() + max_age))
    s = '%s-%s-%s-%s' % (user.id, user.passwd, expires, _COOKIE_KEY)
    L = [user.id, expires, hashlib.sha1(s.encode('utf-8')).hexdigest()]
    return '-'.join(L)

def text2html(text):
    lines = map(lambda s: '<p>%s</p>' % s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'), filter(lambda s: s.strip() != '', text.split('\n')))
    return ''.join(lines)

#根据用户信息拼接一个cookie字符串

def user2cookie(user, max_age):
    #过期时间是当前时间＋设置的有效时间
    expires = str(int(time.time() + max_age))
    #构建cookie存储的信息字符串
    s = '%s-%s-%s-%s' % (user.id, user.passwd, expires, _COOKIE_KEY)
    L = [user.id, expires, hashlib.sha1(s.encode('utf-8')).hexdigest()]
    #分隔
    return '-'.join(L)

#根据cookie字符串，解析出相关用户信息

@asyncio.coroutine
def cookie2user(cookie_str):
    #cookie_str是空则返回
    if not cookie_str:
        return None
    try:
        #通过'-'分割字符串
        L = cookie_str.split('-')
        #如果不是3个元素的话，与我们当初构造sha1字符串不符，返回None
        if len(L) != 3:
            return None
        #分别获得用户id，过期时间和sha1字符串
        uid, expires, sha1 = L
        #如果超时，返回None
        if int(expires) < time.time():
            return None
        #根据用户id查找库，对比有没有该用户
        user = yield from User.find(uid)
        #没有该用户返回None
        if user is None:
            return None
        #根据查到的user的数据构造一个校验sha1字符串
        s = '%s-%s-%s-%s' % (uid, user.passwd, expires, _COOKIE_KEY)
        #比较cookie里的sha1和校验sha1,一样的话，说明当前请求的用户是合法的
        if sha1 != hashlib.sha1(s.encode('utf-8')).hexdigest():
            logging.info('invalid sha1')
            return None
        user.passwd = '******'
        #返回合法的user
        return user
    except Exception as e:
        logging.exception(e)
        return None

#首页，展示接口列表

@get('/')
def index(*, page='1'):
    #获取到要展示的接口页数是第几页
    page_index = get_page_index(page)
    #查找接口表里的条目数
    num = yield from Interface.findNumber('count(id)')
    #通过Page类计算当前页的相关信息
    page = Page(num, page_index)
    #如果表里没有条目，则不需要
    if num == 0:
        interfaces = []
    else:
        #根据计算出来的offset（取的初始条目index）和limit（取的条数），来取出条目
        interfaces = yield from Interface.findAll(orderBy='created_at desc', limit=(page.offset, page.limit))
    #返回给浏览器
    return {
        '__template__': 'interfaces.html',
        'page': page,
        'interfaces': interfaces
    }

#注册页面
@get('/register')
def register():
    return {
        '__template__': 'register.html'
    }

#登录页面

@get('/signin')
def signin():
    return {
        '__template__': 'signin.html'
    }

#登出操作
@get('/signout')
def signout(request):
    referer = request.headers.get('Referer')
    r = web.HTTPFound(referer or '/')
    #清理掉cookie的用户信息数据
    r.set_cookie(COOKIE_NAME, '-deleted-', max_age=0, httponly=True)
    logging.info('user signed signout')

#注册请求
@post('/api/users')
def api_register_user(*, email, name, passwd):
    #判断name是否存在，且是否'\n','\r','\t',' '这种特殊字符
    if not name or name.strip():
        raise APIValueError('name')
    #判断email是否存在，且符合格式
    if not email or not _RE_EMAIL.match(email):
        raise APIValueError('email')
    #判断passwd是否存在，且是否符合格式
    if not passwd  or not _RE_EMAIL.match(passwd):
        raise APIValueError('passwd')

    #查一下库里是否有相同的email地址，如果有的话提示用户email已经被注册过
    users = yield from User.findAll('email=?', [email])
    if len(users) > 0:
        raise APIError('register:failed', 'email', 'Email is already in use')

    #生成一个当前要注册的用户的唯一uid
    uid = next_id()
    #构建shal_passwd
    sha1_passwd = '%s:%s' % (uid, passwd)

    admin = False
    if email == 'zhoushibo@sponia.com':
            admin = True

    #创建一个用户，密码通过sha1加密保存
    user = User(id=uid, name=name.strip(), email=email, passwd=hashlib.sha1(sha1_passwd.encode('utf-8')).hexdigest(), image='http://www.gravatar.com/avatar/%s?d=mm&s=120' % hashlib.md5(email.encode(    'utf-8')).hexdigest(), admin=admin)

    #保存这个用户到数据库用户表
    yield from user.save()
    logging.info('save user OK')
    #构建返回信息
    r = web.Response()
    #添加cookie
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    #只把要返回的实例的密码改成‘******’，库里的密码依然是真实的，以保证真实的密码不会因返回而暴露
    user.passwd = '******'
    #返回的是json数据，所以设置content-type为json的
    r.content_type = 'application/json'
    #把对象转换成json格式返回
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
    return r

#登录请求

@post('/api/authenticate')
def authenticate(*, email, passwd):
    #如果email或passwd为空，都说明有错误
    if not email:
        raise APIValueError('email', 'Invalid email')
    if not passwd:
        raise APIValueError('passwd', 'Invalid passwd')
    #根据email在库里查找匹配的用户
    users = yield from User.findAll('email=?', [email])
    #没有找到用户，返回用户不存在
    if len(users) == 0:
        raise APIValueError('email', 'email not exist')
    #取第一个查到用户，理论上就一个
    user = users[0]
    #按存储密码的方式获取出请求传入的密码字段的sha1值
    sha1 = hashlib.sha1()
    sha1.update(user.id.encode('utf-8'))
    sha1.update(b':')
    sha1.update(passwd.encode('utf-8'))
    #和库里的密码字段的值作比较，一样的话认证成功，不一样的话，认证失败
    if user.passwd != sha1.hexdigest():
        raise APIValueError('passwd', 'Invalid passwd')
    #构建返回信息
    r = web.Response()
    #添加cookie
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    #只把要返回的实例的密码改成'******'，库里的密码依然是正确的，以保证真实的密码不会因返回而暴露
    user.passwd = '******'
    #返回的是json数据，所以设置content-type为json
    r.content_type = 'application/json'
    #把对象转换成json格式返回
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')











































