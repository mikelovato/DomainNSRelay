#!/usr/bin/python3
import socket
import queue
import pymysql
from getopt import getopt
from struct import pack,unpack
from random import randint
from time import time
from sys import argv,exit
from re import match

class DNSserver:
    __TableName = "DNSTable"  # memory dns database name
    __ServerAdd = '8.8.8.8'  # Official DNS table
    __Port = 53  # general dns port
    __QueryQu = queue.Queue()  # request Queue
    __ReQu = queue.Queue()  # response queue
    __Querydict={} # (id,addr)
    __RunTime=65536 # Teminal time
    __InitTime = time()
    def InitDNS(self):
        """
        Reading DNS From TableName
        :return: __TableDNS
        """
        opts, args = getopt(argv[1::], 'd:t:')
        for na, va in opts:
            if '-d'==na:
                if None==match(r'^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$',va):
                    print("Invalid DNS Server,DNS server change to 8.8.8.8")
                else:
                    self.__ServerAdd = va
                    print('Server Address have changed to:', va)
            elif '-t'==na:
                self.__RunTime=int(va)
                print('Server will exit in {} Seconds later'.format(self.__RunTime))
            else:
                print('Invalid parameters,using default parameters!')

    def __GetName(self, DataFrame):
        """
        :param DataFrame:Dns Query Frame
        :return: Query Name
        """
        segs = []
        QueryNameBytes = DataFrame[12:-2]
        i = 0
        count = QueryNameBytes[0]

        while 0 != count:
            segs.append(QueryNameBytes[i + 1:i + count + 1].decode('ascii'))
            i += 1 + count
            count = QueryNameBytes[i]
        return '.'.join(segs)

    def __retrievalDNS(self,QueryName):
        """
        :param QueryName: Query Name
        :return: IP
        """
        db = pymysql.connect("localhost", "**", "***", "****")#release later
        cursor = db.cursor()#使用cursor（）方法获取操作游标
        sql="SELECT address from "+self.__TableName+" where name='"+QueryName+"'"
        try :
            cursor.execute(sql)
            ans= cursor.fetchall()
            ans = ans.__str__()
            ans = ans[3:-5]
        except:
            ans=''
        finally:
            cursor.close()
            db.close()
        return ans

    def __PackageAns(self,Receiveframe, Result, Filtered):
        """
        :param Receiveframe:received data frame
        :param ans_ip:Query Answer
        :param filtered:
        :return: Result Frame
        """
        TargetId = Receiveframe[0:2]# Header
        QueryCount = b'\x00\x01'  # same as query
        if not Filtered:
            Flags = b'\x81\x80'  # diff from query & response [2:4], the same [5::]
            AnswerRRs = b'\x00\x01'  # default : only 1 answer, un-auth
        else:
            Flags = b'\x81\x83'  # rcode = 3, domain does not exist
            AnswerRRs = b'\x00\x00'  # no RRs
        Header = TargetId + Flags + QueryCount + AnswerRRs + b'\x00\x00' + b'\x00\x00'# default Frame model
        Queries = Receiveframe[12::]  # the same as DNS query
        Name = b'\xc0\x0c'  # name pointer
        Type = b'\x00\x01'  # A
        AnswerClass = b'\x00\x01'  # IN
        TTL = pack('!L', 46)  # default
        DataLength = pack('!H', 4)
        IPNumer = Result.split('.')  # *.*.*.* -> hex(*), hex(*), ...
        Address = pack('!BBBB', int(IPNumer[0]), int(IPNumer[1]), int(IPNumer[2]), int(IPNumer[3]))
        Answers = Name + Type + AnswerClass + TTL + DataLength + Address
        return Header + Queries + Answers

    def EstablishServer(self):
        """
        Creating Local DNS Relay Server
        Binding 127.0.0.1:53
        :return: DNS answer or 404
        """
        #release later

    def __GetAdress(self,QueryFrame):
        """
        :param QueryFrame:Query Massage Frame
        :return: IP,type=String
        """
        Ad1,Ad2,Ad3,Ad4=unpack('!BBBB',QueryFrame[-4::])
        return str(Ad1)+'.'+str(Ad2)+'.'+str(Ad3)+'.'+str(Ad4)

    def __SendToRemote(self,Server,Frame,Address):
        """
        :param Server: target Server Address
        :param Frame:
        :param Address:
        :return:
        """
        TempId = unpack('!H',Frame[0:2])
        if TempId[0] in self.__Querydict:
            UpdateID = (2 * TempId[0] + randint(10000, 65535)) % 65536
            Frame = pack('!H', UpdateID) + Frame[2::]
            self.__Querydict[UpdateID] = (TempId[0], Address)
        else:
            self.__Querydict[TempId[0]] = (TempId[0], Address)
        Server.sendto(Frame, (self.__ServerAdd, self.__Port))

    def QueryRemote(self):
        """
        Handle Unknown Name
        :return:
        """
        #release later
