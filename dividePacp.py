'''
TCP 分流
'''
import scapy
from scapy.all import *
from scapy.utils import PcapReader
from scapy.layers import http
import os
def generatePath(path,filename,randnum):
    filepath=os.path.join(path,filename+str(randnum)+'.pcap')
    return filepath

def readaPcap(in_path,save_path,filename,num):
    print("******begin work******")
    packets = rdpcap(in_path)
    judgelist = ['', '', '', '']
    replace = {}
    packlist = {}
#    print("******begin read******")
    for p in packets:
        # if(p.payload.payload.payload.name!='Raw'):
        #     continue
        # print(p.show())
        checklist = []

        # 四元组提取
        nowsrc = str(p.payload.getfieldval('src'))
        nowdst = str(p.payload.getfieldval('dst'))
        checklist.append(nowsrc)
        checklist.append(nowdst)
        checklist.append(str(p.payload.payload.getfieldval('sport')))
        checklist.append(str(p.payload.payload.getfieldval('dport')))

        checklist.sort()
        pstr=""
        for i in checklist:
            pstr=pstr+str(i)+'_'
        if(pstr not in packlist):
            packlist[pstr]=[]

        if(nowsrc<nowdst):
            p.payload.setfieldval('src', '192.0.0.1')
            p.payload.setfieldval('dst', '192.0.0.2')
        else:
            p.payload.setfieldval('src', '192.0.0.2')
            p.payload.setfieldval('dst', '192.0.0.1')

        packlist[pstr].append(p)

    length=0
    for itemlist in packlist.values():
        print(len(itemlist))
        length+=len(itemlist)
        if (len(itemlist) > 5):
            wrpcap(generatePath(save_path, filename, num), itemlist)
            num += 1
    print("-----",length,"-----")
    return num

def dividemorePacp(in_path, save_path, filename, num):
        print("******begin work******")
        packets = rdpcap(in_path)
        packlist = []
        temp=0
        for p in packets:
            temp+=1
            packlist.append(p)
            if(temp%1000==0):
                num+=1
                print(temp/1000)
                wrpcap(generatePath(save_path, filename, num), packlist)
                packlist=[]
        return  num

def dividePacp(read_path):
    filelist = os.listdir(read_path)
    pathlist = []
    for file in filelist:
        if os.path.splitext(file)[1] == '.pcap':
            pathlist.append(os.path.join(read_path,file))
    num=0
    return pathlist

if __name__=='__main__':
    num=0
    pathlist=dividePacp('.\\dataset\\MaliciousDoH-dnscat2-1')
    for path in pathlist:
        num = readaPcap(path,'.\\dataset\\finalData\\Malicious', 'doh_tunnel',num)