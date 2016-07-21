'''
async web application.
'''

import logging; logging.basicConfig(level=logging.INFO)

import asyncio, os, json, time
from datetime import datetime

from aiohttp import web
from jinja2 import Environment, FileSystemLoader

from config import configs
import orm

from web_frame import add_routes, add_static
from handlers import cookie2user, COOKIE_NAME

import pdb

def init_jinja2(app, **kw):
    logging.info('init jinja2...')
    #初始化配置模版，包括模版运行代码的开始结束标志符，变量的开始结束标志符等
    options = dict(
        #是否转义设置为true，就是在渲染模版时自动把变量中的<>&等字符转换为&lt;&gt;&amp;
        autoescape=kw.get('autoescape', True),
        block_start_string=kw.get('block_start_string', '{%'), #运行代码的开始标志符
        block_end_string=kw.get('block_end_string', '%}'), #运行代码的结束标志符
        variable_start_string=kw.get('variable_start_string', '{{'), #变量开始标志符
        variable_end_string=kw.get('variable_end_string', '}}'), #变量结束标志符
        # Jinja2会在使用Template时检查模板文件的状态，如果模板有修改，则重新加载模板。如果对性能要求较高，可将此设置为False
        auto_reload=kw.get('auto_reload', True)
    )
    #从参数中获取path字段，即模板文件的位置
    path = kw.get('path', None)
    #如果没有，则默认为当前文件目录下的templates目录
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    logging.info('set jinja2 template path: %s' % path)
    #Environment是Jinja2中的一个核心类，它的实例用来保存配置，全局变量，以及从本地文件系统或其它位置加载模板。
    #这里把要加载的模板和配置传给Environment,生成Environment实例
    env = Environment(loader=FileSystemLoader(path), **options)
    #从参数取filter字段
    #filters: 一个字典描述的filters过滤器集合，如果非模板被夹在的时候，可以安全的添加filters或移除较早的
    filters = kw.get('filters', None)
    #如果有传入的过滤器设置，则设置为env的过滤器集合
    if filters is not None:
        for name, f in filters.items():
            env.filters[name] = f
    #给webapp设置模板
    app['__templating__'] = env

@asyncio.coroutine
def logger_factory(app, handler):
    @asyncio.coroutine
    def logger(request):
        logging.info('Request: %s %s' % (request.method, request.path))
        return (yield from handler(request))
    return logger

@asyncio.coroutine
def auth_factory(app, handler):
    @asyncio.coroutine
    def auth(request):
        logging.info('check user: %s %s' % (request.method, request.path))
        request.__user__ = None
        cookie_str = request.cookies.get(COOKIE_NAME)
        if cookie_str:
            user = yield from cookie2user(cookie_str)
            if user:
                logging.info('set current user: %s' % user.email)
                request.__user__ = user
        if request.path.startswith('/manage/') and (request.__user__ is None or not request.__user__.admin):
            return web.HTTPFound('/signin')
        return (yield from handler(request))
    return auth

#响应处理
#服务端收到一个请求后的方法调用顺序是：
#logger_facyory->response_factory->RequestHandler().__call__->get或post->handler
#结果处理的情况为：由handler构造出要返回的具体对象，然后在这个返回的对象上加上'__methon__'和'__route__'属性，以标识这个对象并使接下来的程序容易处理
#RequestHandler目的就是从URL函数中分析其需要接收的参数，从request中获取必要的参数，调用URL函数，然后把结果返回给response_factory
#esponse_factory在拿到经过处理后的对象，经过一系列对象类型和格式的判断，构造出正确web.Response对象，以正确的方式返回给客户端
# 在这个过程中，我们只用关心我们的handler的处理就好了，其他的都走统一的通道，如果需要差异化处理，就在通道中选择适合的地方添加处理代码。
# 在response_factory中应用了jinja2来套用模板

@asyncio.coroutine
def response_factory(app, handler):
    @asyncio.coroutine
    def response(request):
        logging.info('Response handler...')
        #调用相应的handler处理request
        #pdb.set_trace()
        r = yield from handler(request)
        logging.info('r = %s' % str(r))
        #如果响应结果为web.StreamResponse类，则直接把它作为响应返回
        if isinstance(r, web.StreamResponse):
            return r
        #如果响应结果为字节流，则把字节流塞到response的body里，设置响应类型为流类型，返回
        if isinstance(r, bytes):
            resp = web.Response(body=r)
            resp.content_type = 'application/octet-stream'
            return resp
        #如果响应结果为字符串
        if isinstance(r, str):
            #先判断是否需要重定向，是的话直接用重定向的地址重定向
            if r.startswith('redirect:'):
                return web.HTTPFound(r[9:])
            #不是重定向，把字符串当作html代码来处理
            resp = web.Response(body=r.encode('utf-8'))
            resp.content_type = 'text/html;charset=utf-8'
            return resp
        #如果结果为字典
        if isinstance(r, dict):
            #先查一下有没有‘__template__’为key的值
            template = r.get('__template__')
            #如果没有，说明要返回json字符串，则把字典转换为json返回，对应的response类型为json类型
            if template is None:
                resp = web.Response(body=json.dumps(
                    r, ensure_ascii=False, default=lambda o: o.__dict__).encode('utf-8'))
                resp.content_type = 'application/json;charset=utf-8'
                return resp
            else:
                r['__user__'] = request.__user__
                # 如果有'__template__'为key的值，则说明要套用jinja2的模板，'__template__'Key对应的为模板网页所在位置
                resp = web.Response(body=app['__templating__'].get_template(template).render(**r).encode('utf-8'))
                resp.content_type = 'text/html;charset=utf-8'
                #以html的形式返回
                return resp
        #如果响应结果为int
        if isinstance(r, int) and r >= 100 and r < 600:
            return web.Response(r)
        #如果响应结果为tuple且数量为2
        if isinstance(r, tuple) and len(r) == 2:
            t, m = r
            #如果tuple的第一个元素是int类型且在100到600之间，这里应该是认定为t为http状态码，m为错误描述
            #或者是服务端自己定义的错误码+描述
            if isinstance(t, int) and t >= 100 and t < 600:
                return web.Response(status=t, text=str(m))
            #default:默认直接以字符串输出
            resp = web.Response(body=str(r).encode('utf-8'))
            resp.content_type = 'text/plain;charset=utf-8'
            return resp
    return response

def datetime_filter(t):
    delta = int(time.time() - t)
    if delta < 60:
        return u'1分钟前'
    if delta < 3600:
        return u'%s分钟前' % (delta // 60)
    if delta < 86400:
        return u'%s小时前' % (delta // 3600)
    if delta < 604800:
        return u'%s天前' % (delta // 86400)
    dt = datetime.fromtimestamp(t)
    return u'%s年%s月%s日' % (dt.year, dt.month, dt.day)

@asyncio.coroutine
def init(loop):
    #创建数据库连接池，DB参数传配置文件里的DB
    yield from orm.create_pool(loop=loop, **configs.db)
    #middlewares设置两个中间处理函数
    #middlewares中的每个factory接受两个参数，app和handler(即middlewares中的下一个handler)
    #比如这里的logger_factory的handler参数其实就是response_factory()
    #middlewares的最后一个元素的Handler会通过routes查找到相应的，其实就是routes注册的handler
    app = web.Application(loop=loop, middlewares=[logger_factory, auth_factory, response_factory])
    # 初始化jinja2模板
    init_jinja2(app, filters=dict(datetime=datetime_filter))
    # 添加请求的handlers，即各请求相对应的处理函数
    add_routes(app, 'handlers')
    # 添加静态文件所在地址
    add_static(app)
    srv = yield from loop.create_server(app.make_handler(), '127.0.0.1', 9000)
    logging.info('server started at http://127.0.0.1:9000...')
    return srv

loop = asyncio.get_event_loop()
loop.run_until_complete(init(loop))
loop.run_forever()
