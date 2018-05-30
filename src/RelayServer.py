from socket import socket, AF_INET, SOCK_DGRAM, error, timeout
from queue import Queue
from pymysql import connect, DataError, MySQLError
from getopt import getopt
from struct import pack, unpack
from random import randint
from time import time
from sys import argv, exit
from re import match


class DNSserver:
    def __init__(self):
        """
        Reading DNS From TableName
        :return: __TableDNS
        """
        self.__TableName = "DNSTable"  # memory dns database name
        self.__ServerAdd = '10.3.9.5'  # Official DNS table
        self.__Port = 53  # general dns port
        self.__QueryQu = Queue()  # request Queue
        self.__ReQu = Queue()  # response queue
        self.__Querydict = {}  # (id,addr)
        self.__RunTime = 65536  # Teminal time
        self.__InitTime = time()
        self.__tempdict = {}
        self.__dictSize = 128

        opts, args = getopt(argv[1::], 'd:t:s:')
        for na, va in opts:
            if '-d' == na:
                if match(r'^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$', va):
                    self.__ServerAdd = va
                    print('Server Address have changed to:', va)
                else:
                    print("Invalid DNS Server,DNS server change to ", self.__ServerAdd)
            elif '-t' == na:
                self.__RunTime = int(va)
                print('Server will exit in {} Seconds later'.format(self.__RunTime))
            elif '-s' == na:
                temp = int(va)
                if temp < 32:
                    self.__dictSize = 0
                elif temp < 1025:
                    self.__dictSize = temp
                    print("Memory size has change to ", temp)
                else:
                    print("Memory Size should be more than 31 and less than 1025")
            else:
                print('Invalid parameters,using default parameters!')

    @staticmethod
    def __GetName(DataFrame):
        segs = []
        QueryNameBytes = DataFrame[12:-2]
        temppara = 0
        count = QueryNameBytes[0]
        while 0 != count:
            segs.append(QueryNameBytes[temppara + 1:temppara + count + 1].decode('ascii'))
            temppara += 1 + count
            count = QueryNameBytes[temppara]
        return '.'.join(segs)

    def __retrievalDNS(self, QueryName):
        db = connect("localhost", "wx", "password", "mytest")
        cursor = db.cursor()  # 使用cursor（）方法获取操作游标
        sql = "SELECT address FROM " + self.__TableName + " WHERE name='" + QueryName + "'"
        try:
            cursor.execute(sql)
            ans = cursor.fetchall()
            ans = ans.__str__()
            ans = ans[3:-5]
        except DataError as e:
            print('Data Error:', e)
            ans = ''
        except MySQLError as e:
            print('MysqlERROR:', e)
            ans = ''
        finally:
            cursor.close()
            db.close()
        return ans

    @staticmethod
    def __PackageAns(Receiveframe, midResult, isFiltered):
        if not isFiltered:
            Flags = b'\x81\x80'  # diff from query & response [2:4], the same [5::]
            AnswerRRs = b'\x00\x01'  # default : only 1 answer, un-auth
        else:
            Flags = b'\x81\x83'  # rcode = 3, domain does not exist
            AnswerRRs = b'\x00\x00'  # no RRs
        IPNumer = midResult.split('.')
        Address = pack('!BBBB', int(IPNumer[0]), int(IPNumer[1]), int(IPNumer[2]), int(IPNumer[3]))
        Answers = b'\xc0\x0c' + b'\x00\x01' + b'\x00\x01' + pack('!L', 46) + pack('!H', 4) + Address
        return Receiveframe[0:2] + Flags + b'\x00\x01' + AnswerRRs + b'\x00\x00' + b'\x00\x00' + Receiveframe[
                                                                                                 12::] + Answers

    def EstablishServer(self):
        """
        Creating Local DNS Relay Server
        Binding 127.0.0.1:53
        :return: DNS answer or 404
        """
        print('Creating local DNS Server...\nLink To Remote DNS Server:', self.__ServerAdd)
        with socket(AF_INET, SOCK_DGRAM) as s:
            print('Bind Socket [{ip}:{po}]...'.format(ip='127.0.0.1', po=self.__Port))
            s.settimeout(1)
            s.bind(('127.0.0.1', self.__Port))
            while True:
                if int(time() - self.__InitTime) > self.__RunTime:  # judge if time lost
                    print('Time Lost,bye!')
                    exit()
                try:
                    while not self.__ReQu.empty():  # if ReQu not empty,send it
                        ans, resource = self.__ReQu.get()
                        s.sendto(ans, resource)  # UDP send
                    data, addr = s.recvfrom(1024)  # buffer size
                    if data[2:4] == b'\x01\x00' and data[-4:-2] == b'\x00\x01':
                        QueryName = self.__GetName(data)
                        print(QueryName)
                        if self.__dictSize and QueryName in self.__tempdict:
                            s.sendto(self.__PackageAns(data, self.__tempdict[QueryName], False), addr)
                            continue
                        ResultAdd = self.__retrievalDNS(QueryName)
                        if '0.0.0.0' == ResultAdd:
                            s.sendto(self.__PackageAns(data, ResultAdd, True), addr)  # UDP Send
                        elif 6 < len(ResultAdd):
                            s.sendto(self.__PackageAns(data, ResultAdd, False), addr)
                        else:
                            self.__QueryQu.put((data, addr))
                except error:
                    continue
                except timeout:
                    continue
                except Exception as e:
                    print('Unexpected error', e)

    @staticmethod
    def __GetAdress(QueryFrame):
        Ad1, Ad2, Ad3, Ad4 = unpack('!BBBB', QueryFrame[-4::])
        return str(Ad1) + '.' + str(Ad2) + '.' + str(Ad3) + '.' + str(Ad4)

    def __SendToRemote(self, Server, Frame, Address):
        TempId = unpack('!H', Frame[0:2])
        if TempId[0] in self.__Querydict:
            UpdateID = (2 * TempId[0] + randint(10000, 65535)) % 65536
            Frame = pack('!H', UpdateID) + Frame[2::]
            self.__Querydict[UpdateID] = (TempId[0], Address)
        else:
            self.__Querydict[TempId[0]] = (TempId[0], Address)
        Server.sendto(Frame, (self.__ServerAdd, self.__Port))

    def QueryRemote(self):
        with socket(AF_INET, SOCK_DGRAM) as s:
            s.bind(('', 9999))
            s.settimeout(1)
            while True:
                if int(time() - self.__InitTime) > self.__RunTime:
                    print('Time Lost,bye!')
                    exit()
                try:
                    # For Query queue,send to remote Server
                    while not self.__QueryQu.empty():
                        Frame, Address = self.__QueryQu.get()
                        self.__SendToRemote(s, Frame, Address)
                    Data, Addr = s.recvfrom(1024)  # buffer size
                    TempId = unpack('!H', Data[0:2])
                    naam = self.__GetName(Data)
                    if self.__dictSize and naam not in self.__tempdict:
                        if len(self.__tempdict) > self.__dictSize:
                            self.__tempdict.popitem()
                        self.__tempdict[naam] = self.__GetAdress(Data)
                    Sourcid, Sourcaddr = self.__Querydict[TempId[0]]

                    self.__ReQu.put((pack('!H', Sourcid) + Data[2::], Sourcaddr))
                    self.__Querydict.pop(TempId[0])
                except error:
                    continue
                except timeout:
                    continue
                except Exception as e:
                    print('Unexpected error', e)
