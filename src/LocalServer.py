"""
    设计一个DNS服务器程序,读入“IP地址-域名(事先编好)”对照表,当客户端查询域名对应的IP地址时,用域名检索该对照表,有三种可能的检索结果
    1. 检索结果,IP地址0.0.0.0,则向客户端返回“域名不存在”报错信息(不良网站安拦截功能)
    2. 检索结果:普通IP地址,则向客户端返回地址(服务器功能)
    3. 表中未捡到该域名,则向因特网DNS服务器查询,并将结果返回到客户端(中继功能)
        * 考虑多个计算机上的客户端会同时查询,需要进行信息ID的转换
        * 考虑并发
        * 考虑终端截图的底色
        * Socket编程
"""
from RelayServer import DNSserver
from threading import Thread

if __name__ == '__main__':
    tem = DNSserver()  # 'tem' means Temp
    handle_ans = Thread(target=tem.QueryRemote, args=())
    handle_query = Thread(target=tem.EstablishServer, args=())
    handle_ans.start()
    handle_query.start()
    handle_query.join()
    handle_ans.join()
