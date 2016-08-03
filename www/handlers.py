#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'url handlers'

import re, time, json, logging, hashlib, base64, asyncio

import markdown2

from aiohttp import web
from web_frame import get, post
from apis import Page, APIValueError, APIResourceNotFoundError, APIError

from models import User, Comment, Interface, next_id

from config import configs

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

#首页，展示API列表

@get('/')
def index(*, page='1'):
    #获取到要展示的API页数是第几页
    page_index = get_page_index(page)
    #查找API表里的条目数
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
    return r

#注册请求
@post('/api/users')
def api_register_user(*, email, name, passwd):
    logging.info('api_register_user...')
    #判断name是否存在，且是否'\n','\r','\t',' '这种特殊字符
    if not name or not name.strip():
        raise APIValueError('name')
    #判断email是否存在，且符合格式
    if not email or not _RE_EMAIL.match(email):
        logging.info('email api_register_user...')
        raise APIValueError('email')
    #判断passwd是否存在，且是否符合格式
    if not passwd  or not _RE_SHA1.match(passwd):
        logging.info('passwd api_register_user...')
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
    logging.info("call authenticate---------------------")
    #如果email或passwd为空，都说明有错误
    if not email:
        raise APIValueError('email', 'Invalid empty email')
    if not passwd:
        raise APIValueError('passwd', 'Invalid empty passwd')
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
        logging.info('passwd authenticate...sha1:%s,passwd:%s'%(sha1.hexdigest(), user.passwd))
        raise APIValueError('passwd', 'Invalid passwd match')
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
    return r


#评论管理页面
@get('/manage/')
def manage():
    return 'redirect:/manage/comments'

@get('/manage/comments')
def manage_comments(*, page='1'):
    #查看所有评论
    return {
        '__template__': 'manage_comments.html',
        'page_index': get_page_index(page)
    }

@get('/api/comments')
def api_comments(*, page='1'):
    page_index = get_page_index(page)
    num = yield from Comment.findNumber('count(id)')
    p = Page(num, page_index)
    if num == 0:
        return dict(page=p, comments=())
    comments = yield from Comment.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))
    return dict(page=p, comments=comments)

@post('/api/interfaces/{id}/comments')
def api_create_comment(id, request, *, content):
    #对某个API发表评论
    user = request.__user__
    #评论必须为登录状态下
    if user is None:
        raise APIPermissionError('content')
    #评论不能为空
    if not content or not content.strip():
        raise APIValueError('content')
    #查询APIid是否有对应API
    interface = yield from Interface.find(id)
    if interface is None:
        raise APIResourceNotFoundError('Interface')
    #构建一条评论数据
    comment = Comment(interface_id=interface.id, user_id=user.id, user_name=user.name, user_image=user.image, content=content.strip())
    #保存到评论里
    yield from comment.save()
    return comment


@post('/api/comments/{id}/delete')
def api_delete_comments(id, request):
    #delete a comment
    logging.info(id)
    #管理员检查
    check_admin(request)
    #查询评论id是否有评论
    c = yield from Comment.find(id)
    if c is None:
        raise APIResourceNotFoundError('Comment')
    yield from c.remove()


###########用户管理##############
@get('/show_all_users')
def show_all_users():
    #显示所有用户
    users = yield from User.findAll()
    logging.info('to index...')

    return {
        '__template__': 'test.html',
        'users': users
    }

@get('/api/users')
def api_get_users(request):
    #返回所有用户信息的json格式
    users = yield from User.findAll(orderBy='created_at desc')
    logging.info('users = %s and type = %s' % (users, type(users)))
    for u in users:
        u.passwd = '******'
    return dict(users=users)

@get('/manage/users')
def manage_users(*, page='1'):
    #查看所有用户
    return {
        '__template__': 'manage_users.html',
        'page_index': get_page_index(page)
    }

#################API管理的处理函数################

@get('/manage/interfaces/create')
def manage_create_interface():
    #创建API页面
    return {
        '__template__': 'manage_interface_edit.html',
        'id': '',
        'action': '/api/interfaces'
    }

@get('/manage/interfaces')
def manage_interfaces(*, page='1'):
    return {
        '__template__': 'manage_interfaces.html',
        'page_index': get_page_index(page)
    }

@get('/api/interfaces')
def api_interfaces(*, page='1'):
    #获取API信息
    page_index = get_page_index(page)
    num = yield from Interface.findNumber('count(id)')
    p = Page(num, page_index)
    if num == 0:
        return dict(page=p, Interfaces=())
    interfaces = yield from Interface.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))
    return dict(page=p, ineterfaces=interfaces)

@post('/api/interfaces')
def api_create_interface(request, *, name, summary, content):
    #只有管理员可以写API
    check_admin(request)
    #name, summary, content不能为空
    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty')
    if not summary or not summary.strip():
        raise APIValueError('summart', 'summary cannot be empty')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty')

    #根据传入的信息，构建一条API数据
    #logging.info("user id --------------id:%s,name:%s,image:%s,summary:%s"%(request.__user__.id, request.__user__.name, request.__user__.image, request.__user__.summary))
    interface = Interface(user_id=request.__user__.id, user_name=request.__user__.name, user_image=request.__user__.image, name=name.strip(), summary=summary.strip(), content=content.strip())
    #interface = Interface(interface_id=request.__user__.id, interface_name=request.__user__.name, interface_image=request.__user__.image, name=name.strip(), summary=summary.strip(), content=content.strip())
    #保存
    yield from interface.save()
    logging.info("save interface %s"%summary)
    return interface

@get('/interface/{id}')
def get_interface(id):
    #根据APIid查询该API信息
    interface = yield from Interface.find(id)
    #根据APIid查询该API评论
    comments = yield from Comment.findAll('interface_id=?', [id], orderBy='created_at desc')
    #markdown2是个扩展模块，把API正文和评论套入markdown2中
    for c in comments:
        c.html_content = text2html(c.content)
    interface.html_content = markdown2.markdown(interface.content)
    #返回页面
    return {
        '__template__': 'interface.html',
        'interface': interface,
        'comments': comments
    }

@post('/api/interface/{name}')
def interface_response(name):
    #格局APIid获取API返回
    interfaces = yield from Interface.findAll('name=?', [name], orderBy='created_at desc')
    #interface = yield from Interface.findByCondition(name)
    #for interface in interfaces:
    #    return interface.content
    #interface = None
    #for interface in interfaces:
    if len(interfaces) == 1:
        interface = interfaces[0]
    elif len(interfaces) > 1:
        raise APIValueError('name', 'The API name is not unique')
    else:
        raise APIValueError('name', 'Can\'t find %s API' % name)
    interface.content_type = 'application/json'
    return interface.content

@get('/api/interfaces/{id}')
def api_get_interface(*, id):
    #获取某个API的信息
    interface = yield from Interface.find(id)
    return interface

@post('/api/interfaces/{id}/delete')
def api_delete_interface(id, request):
    #删除一个API
    logging.info("删除API的APIID为：%s" % id)
    #检查权限
    check_admin(request)
    #查询评论id是否有对应的评论
    b = yield from Interface.find(id)
    #没有抛出异常
    if b is None:
        raise APIResourceNotFoundError('Comment')
    yield from b.remove()
    return dict(id=id)

@post('/api/interfaces/modify')
def api_modify_interface(request, *, id, name, summary, content):
    #修改一个API
    logging.info("修改的APIID为：%s", id)
    #name, summary, content不能为空
    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty')
    if not summary or not summary.strip():
        raise APIValueError('summary', 'summary cannot be empty')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty')

    #获取指定id的API数据
    interface = yield from Interface.find(id)
    interface.name = name
    interface.summary = summary
    interface.content = content
    #保存
    yield from interface.update()
    return interface

@get('/manage/interfaces/modify/{id}')
def manage_modify_interface(id):
    #修改API界面
    return {
        '__template__': 'manage_interface_modify.html',
        'id': id,
        'action': '/api/interfaces/modify'
    }































