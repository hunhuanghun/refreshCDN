#!/usr/bin/python
# -*- coding: utf-8 -*-
#############################################################################################################################################
## Function:refreshCDN                                                                                                                     ##
##                                                          README                                                                         ##
##  u=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx                                                                                                     ##
##  p=xxxxxxxxxxxxxxxxxxxxxx                                                                                                               ##
##  Users and passwords are changed from time to time and inform you by mail。                                                             ##
##*****************************************************************************************************************************************##
##*****************************************************************************************************************************************##
##Example:                                                                                                                                 ##
##                                                                                                                                         ##
## 1、URL refresh:                                                                                                                         ##
##     Input need to refresh the object's URL (http:// or https://), for example: https://gk.dl.gxpan.cn/kingdoms/1.0.7/graphics/TOC.json  ##
##     The number of daily URL refreshes is no more than 10000;It takes about five minutes to refresh the task.                            ##
##                                                                                                                                         ##
##     python GK_refreshCDN_Tools.py RefreshCdnUrl -u XXXXX -p XXXXXXX --urls https://gk.dl.gxpan.cn/kingdoms/1.0.7/graphics/TOC.json      ##
##     Return:{u'count': 1, u'task_id': u'1505808737243003321'}                                                                            ##
##     See that this information is returned to indicate that the execution is Success; and takes effect in 5 minutes                      ##
##                                                                                                                                         ##
## 2、DIR refresh:                                                                                                                         ##
##    Input need to refresh the directory URL (http:// or https://), there is one in a line, for example: https://gk.dl.gxpan.cn/kingdoms/ ## 
##    The number of daily directory refreshes is not more than 100;It takes about five minutes to refresh the task.                        ##
##                                                                                                                                         ##
##    python GK_refreshCDN_Tools.py RefreshCdnDir -u XXXXX -p XXXXXXX --dirs https://gk.dl.gxpan.cn/kingdoms/                              ##
##    Return:{u'count': 1, u'task_id': u'150580663567614540'}                                                                              ##
##    See that this information is returned to indicate that the execution is Success; and takes effect in 5 minutes                       ##
##                                                                                                                                         ##
##*****************************************************************************************************************************************##
##*****************************************************************************************************************************************##
##Version:                                                                                                                                 ##
## python == 2.6.6 or 2.7.12;requests == 2.18.4;urllib == urllib3                                                                          ##
##                                                                                                                                         ##
## python == 2.6.6 （python 2.6.6 version, in the implementation, there will be a warning, but does not affect the use）                   ##
## Warning:/usr/lib/python2.6/site-packages/urllib3-1.22-py2.6.egg/urllib3/util/ssl_.py:339: SNIMissingWarning: An HTTPS request           ##
## has been made, but the SNI (Subject Name Indication) extension to TLS is not available on this platform. This may cause the server to   ##
## present an incorrect TLS certificate, which can cause validation failures. You can upgrade to a newer version of Python to solve this.  ##
## For more information, see https://urllib3.readthedocs.io/en/latest/advanced-usage.html ssl-warnings SNIMissingWarning)                  ##
## python == 2.7.12 (Python 2.7.12 version, in the implementation, there will be no warning;it is recommended to use Python 2.7.12)        ##
##                                                                                                                                         ##
## requests module:                                                                                                                        ##
## git clone git://github.com/requests/requests.git                                                                                        ##
## cd requests && python setup.py install                                                                                                  ##
##                                                                                                                                         ##
## urllib3 module：                                                                                                                        ##
## git clone git://github.com/shazow/urllib3.git                                                                                           ##
## cd urllib3 && python setup.py install                                                                                                   ##
#############################################################################################################################################

import os
import hashlib
import urllib
import requests
import binascii
import hmac
import copy
import random
import sys
import time
from pprint import pprint
from optparse import OptionParser
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

reload(sys)
sys.setdefaultencoding("utf-8")

try: import simplejson as json
except: import json


class Sign:
    def __init__(self, secretId, secretKey):
        self.secretId = secretId
        self.secretKey = secretKey
    def make(self, requestHost, requestUri, params, method = 'GET'):
        # 生成签名原文字符串，拼接规则为：请求方法 + 请求主机 +请求路径 + ? + 请求字符串
        srcStr = method.upper() + requestHost + requestUri + '?' + "&".join(k.replace("_",".") + "=" + str(params[k]) for k in sorted(params.keys()))
        # 生成签名串,首先使用 HMAC-SHA1 算法对上一步中获得的签名原文字符串进行签名，然后将生成的签名串使用 Base64 进行编码，即可获得最终的签名串。
        hashed = hmac.new(self.secretKey, srcStr, hashlib.sha1)
        return binascii.b2a_base64(hashed.digest())[:-1]

class Request:
    timeout = 10
    version = 'Python_Tools'
    def __init__(self, secretId, secretKey):
        self.secretId = secretId
        self.secretKey = secretKey

    def send(self, requestHost, requestUri, params, files = {}, method = 'GET', debug = 0):
        # 此为传递的请求参数，具体需要哪些请求参数详见：https://cloud.tencent.com/document/product/228/3946
        params['RequestClient'] = Request.version
        params['SecretId'] = self.secretId
        sign = Sign(self.secretId, self.secretKey)
        params['Signature'] = sign.make(requestHost, requestUri, params, method)
        url = 'https://%s%s' % (requestHost, requestUri)

        if debug:
            print method.upper(), url
            print 'Request Args:'
            pprint(params)
        if method.upper() == 'GET':
            req = requests.get(url, params=params, timeout=Request.timeout,verify=False)
        else:
            req = requests.post(url, data=params, files=files, timeout=Request.timeout,verify=False)

        if debug:
            print "Response:", req.status_code, req.text
        if req.status_code != requests.codes.ok:
            #如果发送了一个错误请求(一个 4XX 客户端错误，或者 5XX 服务器错误响应)，我们可以通过 Response.raise_for_status() 来抛出异常
            req.raise_for_status()

        rsp = {}
        try:
            # 使用json来解码返回的内容，如果返回的内容不是json格式，则抛出异常
            rsp = json.loads(req.text)
        except:
            raise ValueError, "Error: response is not json\n%s" % req.text
        # 出参code 0表示成功，其他值表示失败。
        code = rsp.get("code", -1)
        # message，模块错误信息描述，与接口相关
        message = rsp.get("message", req.text)
        if rsp.get('code', -404) != 0:
            raise ValueError, "Error: code=%s, message=%s" % (code, message)
        if rsp.get('data', None) is None:
            print 'request is success.'
        else:
            print rsp['data']
# 将接在_后面的第一个字母大写，如_help --> Help
def Name(name):
    up = False
    new_name = ""
    for i in name:
        if i == '_':
            up = True
            continue
        if up:
            new_name += i.upper()
        else:
            new_name += i
        up = False
    return new_name


class Cdn:
    def __init__(self):
        self.params = {
                'Region': 'gz',
                'Nonce': random.randint(1, sys.maxint),
                'Timestamp': int(time.time()),
                }
        self.files = {}
        self.host = 'cdn.api.qcloud.com'
        self.uri = '/v2/index.php'
        self.method = "POST"
        self.debug = 1

    def parse_args(self):
        actions = []
        # 使用dir查看Cdn类中的所有方法、属性，将首字母为大写的方法放进actions列表中。
        for method in dir(self):
            if method[0].isupper():
                actions.append( method )
        # %prog，optparse 会以当前程序名的字符串来替代：如 os.path.basename.(sys.argv[0])
        usage='usage: %prog Action [options]\nThis is a command line tools to access Qcloud API.\n\nSupport Actions:\n    '+"\n    ".join(actions)
        # 初始化OptionParser类对象，optparse模块可以方便地生成标准的、符合Unix/Posix 规范的命令行说明
        self.parser = OptionParser(usage=usage)
        from sys import argv
        # 判断输入的参数个数如果小于2，且argv[1]不在actions列表中，则输出帮助说明信息
        if len(argv) < 2 or argv[1] not in actions:
            self.parser.print_help()
            return 0

        action = argv[1]
        self.params['Action'] = action
        usage='usage: %%prog Action [options]\n\nThis is help message for action "%s"\nMore Usage: http://www.qcloud.com/wiki/v2/%s' % (action, action)
        # 再次初始化一个OptionParser类对象
        self.parser = OptionParser(usage=usage)
        self.parser.add_option('--debug', dest='debug', action="store_true", default=False, help='Print debug message')
        self.parser.add_option('-u', '--secret_id', dest='secret_id', help='Secret ID from <https://console.qcloud.com/capi>')
        self.parser.add_option('-p', '--secret_key', dest='secret_key', help='Secret Key from <https://console.qcloud.com/capi>')
        # 根据输入的参数，调用对应的函数
        getattr(self, action)()
    
        if len(argv) == 2:
            self.parser.print_help()
            return 0

        (options, args) = self.parser.parse_args() # parse again
        print "options-->:", options
        print "args--->:",args
        print "options.debug:",options.debug
        self.debug = options.debug
        for key in dir(options):
            if not key.startswith("__") and getattr(options, key) is None:
                raise KeyError, ('Error: Please provide options --%s' % key)
 
        
        for option in self.parser.option_list:
            opt = option.dest
            if opt not in [None, 'secret_id', 'secret_key', 'debug']:
                self.params[ Name(opt) ] = getattr(options, opt)

        self.options = options
        method = 'get_params_' + action
        if hasattr(self, method): getattr(self, method)()

        # format params
        for key, value in self.params.items():
            if value == '':
                del self.params[key]
            if isinstance(value, list):
                del self.params[key]
                for idx, val in enumerate(value):
                    self.params["%s.%s"%(key, idx)] = val

        request = Request(options.secret_id, options.secret_key)
        return request.send(self.host, self.uri, self.params, self.files, self.method, self.debug)


    def DescribeCdnHosts(self):
        self.parser.add_option('--offset', dest='offset', default='', help="offset")
        self.parser.add_option('--limit', dest='limit', default='',help="limit")

    def RefreshCdnUrl(self):
        self.parser.add_option('--urls', dest='urls', default=[], action="append", help="Flush the cache of these URLs(use multi --urls)")
        self.parser.add_option('--urls-from', dest='urls_from', default="", metavar="FILE", help="Flush the cache of these URLs(one url per line)")

    def RefreshCdnDir(self):
        self.parser.add_option('--dirs', dest='dirs', default=[], action="append", help="Flush the cache of these DIRs(use multi --dirs)")
        self.parser.add_option('--dirs-from', dest='dirs_from', default="", metavar="FILE", help="Flush the cache of these URLs(one dir per line)")

    def get_params_RefreshCdnUrl(self):
        if self.options.urls_from:
            f = open(self.options.urls_from)
            self.params["urls"] = [p.strip() for p in f.readlines()]
        elif not self.options.urls:
            raise ValueError, "Please provide --urls or --urls-from"
        del self.params['urlsFrom']


def main():
    cdn = Cdn()
    try:
        cdn.parse_args()
    except Exception as e:
        print e
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())

