#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@author zhuzhu
@contact QQ327909056
'''
import dpkt,sys,os,re
import binascii,time,socket
import calc,var
import pdb
import profile

def mfile(files,nFilter,pre_L5node,sig):
    L5node = {}
    L3node={}
    synnode={}
    errornode={}
    spnum=var.maxpl
    scnum=var.maxpc
    #app = os.path.basename(fname)
    #print app
    #print time.time()
    pname=0
    for fname in files:
        try:
            f = file(fname,"rb")
    
            pcap = dpkt.pcap.Reader(f)
        except:
            return {},{},{},fname
            #print "Open "+fname+" file error: maybe not libpcap format pcap file."
            #continue
            #sys.exit()

        #print time.time()
        L5node,L3node,synnode,errornode,spnum,scnum=get_node(pcap,L5node,L3node,synnode,errornode,spnum,scnum,pname,nFilter)
        #print time.time()
        pname+=1

    for key, stream in L5node.items():
        L5node[stream['RL5']]=stream
        del L5node[key]

    get_QPE_result(L5node,sig)
    getsig(L5node,pre_L5node)
    show_content(L5node)
    #print time.time()
    return L5node, L3node,errornode,0

def get_QPE_result(L5node,sig):
    key_list=[]
    str_list=[]
    dpi_result=[]
    for key,stream in L5node.items():
        L5node[key]['protocol']=''


def get_node(pcap,L5node,L3node,synnode,errornode,spnum,scnum,pname,nFilter):
    fnode=[]
    dpktEth=dpkt.ethernet
    #dpktIp=dpkt.ip
    #for ts, buf in pcap:
    try:
        for buf in pcap:
            try:
                eth = dpktEth.Ethernet(buf[1]) #损耗点
                #if eth.type != dpktEth.ETH_TYPE_IP:
                if eth.type != 2048:
                    #因为Linux cooked capture的原因，采用一种取巧的方式先解决下，后面需要从新研究正确的方法
                    if eth.type==0 and eth.data[0:2]=='\x08\x00':
                        eth = dpktEth.Ethernet(buf[1][2:])
                    else:
                        continue
            except:
                continue

            #sip dip sport dport proto pl ...
            ip = eth.data           #损耗点
            try:
                #去掉长度解析，因为有些异常报文，该字段已经出错，现在几万的值，改为直接算content长度
                #packetlength = ip.len-ip.hl*4  #hl

                #if packetnum == 1:
                #    init_ts = ts
                #else ts -= init_ts

                ipp=ip.p
                #if ipp == dpktIp.IP_PROTO_TCP:
                if ipp == 6:
                    #exception handling if ip.len==0
                    if ip.len == 0:
                        for info in synnode:
                            split=info.split('_')
                            #if split[0]==socket.inet_ntoa(ip.src) and split[2]==socket.inet_ntoa(ip.dst) and (ip.id-synnode[info])==1:
                            if split[0]==ip.src and split[2]==ip.dst and (ip.id-synnode[info])==1:
                                del synnode[info]
                                errornode[info]=1
                                break
                    ipData=ip.data      #损耗点
                    #packetlength = packetlength - ipData.off*4
                    sequence=ipData.seq
                    flags=ipData.flags
                    proto='TCP'
                    #print ( ip.data.flags & dpkt.tcp.TH_FIN )  != 0
                    #print "%s : tcp, %s, %s, %4s" % (ts,ip.ttl,ip.len,ip.src)
                #elif ipp == dpktIp.IP_PROTO_UDP:
                elif ipp == 17:
                    ipData=ip.data      #损耗点
                    #packetlength = packetlength - 8
                    sequence=None
                    flags=None
                    proto='UDP'
                    #print "%s : udp, %s, %s, %4s" % (ts,ip.ttl,ip.len,ip.src)
                else:
                    #print ip.p
                    continue
            except:
                continue
            #print sport, dport, packetlength
            try:
                #src = socket.inet_ntoa(ip.src) #Convert an IP address from 32-bit packed binary format to a string format.
                #dst = socket.inet_ntoa(ip.dst) #性能怎么样，又一次消耗特征大，然后没有出现？
                '''
                ipsrc=[str(ord(z)) for z in ip.src]
                ipdst=[str(ord(z)) for z in ip.dst]
                src='.'.join(ipsrc)
                dst='.'.join(ipdst)
                '''
                src=ip.src
                dst=ip.dst
                sport = str(ipData.sport)
                dport = str(ipData.dport)
            except:
                continue
            #if (nFilter.has_key(sport) and nFilter[sport]['state']) or (nFilter.has_key(dport) and nFilter[dport]['state']):
            if (sport in nFilter and nFilter[sport]['state']) or (dport in nFilter and nFilter[dport]['state']):
                continue
            content=ipData.data
            packetlength=len(content)
            #因为IP字符含有'_'所以使用8个'_'来区分
            L5 ='_'.join([src,sport,dst,dport,proto])
            L5d='_'.join([dst,dport,src,sport,proto])

            if packetlength <= 0 and flags != 2:
                #if synnode.has_key(L5):
                if L5 in synnode:
                    synnode[L5]=ip.id
                continue

            if flags == 2:
                #存在一些错误，第一个包是syn包，第二个包也是syn包，对这些包进行忽略
                #if synnode.has_key(L5) or synnode.has_key(L5d):
                if L5 in synnode or L5d in synnode:
                    continue
                synnode[L5]=ip.id
                continue
            '''
            if [proto,sport] in var.fpro or [proto,dport] in var.fpro:
                continue
            '''
            '''
            for kw in var.fkey:
                if kw in content:
                    fnode.append(L5)
                    break
            '''
            if L5 in fnode or L5d in fnode:
                continue

            #if proto == 'TCP' and synnode.has_key(L5) == False and synnode.has_key(L5d)==False:
            if proto == 'TCP' and L5 not in synnode and L5d not in synnode:
                #if errornode.has_key(L5) == False and errornode.has_key(L5d)==False:
                if L5 not in errornode and L5d not in errornode:
                    errornode[L5]=1
                continue

            #if  L5node.has_key(L5d):
            if L5d in L5node:
                L5nodeL5d=L5node[L5d]
                L5nodeL5d['size']+=packetlength
                if len(L5nodeL5d['apl']) < spnum:
                    L5nodeL5d['apl'].append(str(packetlength))
                continue
            #elif L5node.has_key(L5):
            elif L5 in L5node:
                L5nodeL5=L5node[L5]
                L5nodeL5['size']+=packetlength
                if len(L5nodeL5['apl']) < spnum:
                    L5nodeL5['apl'].append(packetlength)
                '''
                else:
                    continue
                '''
                #if len(L5node[L5]['session']['content']) < scnum or proto=='UDP':
                if len(L5nodeL5['session']['pl'])<scnum:
                    if sequence:
                        if sequence in L5nodeL5['session']['sequence']:
                            L5nodeL5['size']-=packetlength
                            continue
                    L5nodeL5['session']['pl'].append(packetlength)
                    L5nodeL5['session']['content'].append(content)
                    L5nodeL5['session']['sequence'].append(sequence)
                else:
                    continue
            else:
                src=socket.inet_ntoa(src)
                dst=socket.inet_ntoa(dst)
                RL5='_'.join([src,sport,dst,dport,proto])
                L5node[L5]={}
                L5nodeL5=L5node[L5]
                L5nodeL5['RL5']=RL5
                L5nodeL5['pname']=str(pname)
                L5nodeL5['size']=packetlength
                L5nodeL5['apl']=[packetlength]
                L5nodeL5['time']=buf[0]
                L5nodeL5['session']={}
                L5nodeL5['session']['pl']=[packetlength]
                L5nodeL5['session']['content']=[content]
                L5nodeL5['session']['sequence']=[sequence]
                L3s='_'.join(['S'+proto,src,sport])
                L3d='_'.join(['D'+proto,dst,dport])
                #对于多个域名或者多个UA对应同一个IP+PORT的情况（P2P下载中经常出现该种情况），重新归类
                #使用有些UA是非明文，所以采用了binascii.b2a_hex
                if content[0:4] in var.rule:
                    MD=content[0:4]
                    if 'Host:' in content:
                        DM=binascii.b2a_hex(content.replace('_','@').split('Host:')[1].split('\r\n')[0])
                    else:
                        DM=''
                    if 'User-Agent:' in content:
                        UA=binascii.b2a_hex(content.replace('_','@').split('User-Agent:')[1].split('\r\n')[0])
                    else:
                        UA=''
                    newL5='_'.join([RL5,DM,UA,MD])
                    L3s='_'.join([L3s,DM,UA,MD])
                    L3d='_'.join([L3d,DM,UA,MD])
                    L5nodeL5['newkey']=newL5
                if dport=='443' and content[0]=='\x16':
                    newL5='_'.join([RL5,'v1'])
                    L3s='_'.join([L3s,'v1'])
                    L3d='_'.join([L3d,'v1'])
                    L5nodeL5['ssl']=newL5
                has_key_deal(L3node,L3s,packetlength,content,buf[0])
                has_key_deal(L3node,L3d,packetlength,content,buf[0])
                #连接的识别结果
                #格式：(TCP|UDP)(1)+SIP(4)+SPORT(2)+DIP(4)+DPORT(2)+SIZE(2)+CONTENT(N)
                hex_sport="0000"+hex(ipData.sport)[2:]
                str_sport=hex_sport[len(hex_sport)-4:]
                hex_dport="0000"+hex(ipData.dport)[2:]
                str_dport=hex_dport[len(hex_dport)-4:]
                hex_size="0000"+hex(len(content))[2:]
                str_size=hex_size[len(hex_size)-4:]
                in_str=binascii.b2a_hex(chr(ipp))+binascii.b2a_hex(ip.src)+str_sport+binascii.b2a_hex(ip.dst)+str_dport+str_size+binascii.b2a_hex(content)
                #dpi_result=os.popen(r'QPE.exe Z H U '+in_str).read()
                #L5nodeL5['protocol']=dpi_result.decode('gbk').encode('utf-8')
                #print dpi_result
                L5nodeL5['in_str']=in_str
    except:
        pass
    return L5node,L3node,synnode,errornode,spnum,scnum                


def has_key_deal(node,key,packetlength,content,ts):
    #if node.has_key(key):
    if key in node:
        nodeKey=node[key]
        nodeKey['pl'].append(packetlength)
        nodeKey['content'].append(content)
        nodeKey['time'].append(ts)
    else:
        node[key]={}
        nodeKey=node[key]
        nodeKey['pl']=[packetlength]
        nodeKey['content']=[content]
        nodeKey['sub']=[]
        nodeKey['size']=0
        nodeKey['time']=[ts]

def show_content(node):
    '''
    need_change_list=[]
    for num in xrange(256):
        if (0x19<num<0x7f and num != 0x3c and num !=0x3e) or num==0x0a or num==0x0d:
            need_change_list.append(False)
        else:
            need_change_list.append(True)
    '''
    for key, stream in node.items():
        realnode=stream['session']
        showcontent=[]
        minlen=3
        #因为目前只显示每个连接的第一个包，所以后面的包暂时没显示，可以忽略，先提高下性能
        #for cont in realnode['content']:
        cont=realnode['content'][0]
        if True:
            showchar=''
            charb2a=binascii.b2a_hex(cont)
            #showchar=['' for z in xrange(2000)]
            #y=0
            temp=0
            clen=len(cont)
            minlen=3
            if clen<minlen:
                '''
                for char in cont:
                    showchar+=binascii.b2a_hex(char)+' '
                    #showchar[y]=binascii.b2a_hex(char)+' '
                    #y=y+1
                '''
                for i in xrange(clen):
                    showchar+=charb2a[2*i:2*i+2]+' '
            else:
                x=0
                while(x<clen):
                    if calc.needChange(cont[x]):
                    #if need_change_list[int(charb2a[2*x:2*x+2])]:
                        if temp:
                            '''
                            showchar+=' '+binascii.b2a_hex(cont[x])+' '
                            #showchar[y]=' '+binascii.b2a_hex(cont[x])+' '
                            #y=y+1
                            '''
                            showchar+=' '+charb2a[2*x:2*x+2]+' '
                        else:
                            '''
                            showchar+=binascii.b2a_hex(cont[x])+' '
                            #showchar[y]=binascii.b2a_hex(cont[x])+' '
                            #y=y+1
                            '''
                            showchar+=charb2a[2*x:2*x+2]+' '
                        temp=0
                        x=x+1
                    elif (x+1<clen) and calc.needChange(cont[x+1]):
                    #elif (x+1<clen) and need_change_list[int(charb2a[2*(x+1):2*(x+1)+2])]:
                        if temp:
                            '''
                            showchar+=cont[x]
                            showchar+=' '+binascii.b2a_hex(cont[x+1])+' '
                            #showchar.append(cont[x])
                            #showchar[y]=cont[x]+' '+binascii.b2a_hex(cont[x+1])+' '
                            #y=y+1
                            '''
                            showchar+=cont[x]
                            showchar+=' '+charb2a[2*(x+1):2*(x+1)+2]+' '
                        else:
                            '''
                            showchar+=' '+binascii.b2a_hex(cont[x])+' '
                            showchar+=binascii.b2a_hex(cont[x+1])+' '
                            #showchar.append(' '+binascii.b2a_hex(cont[x])+' ')
                            #showchar[y]=' '+binascii.b2a_hex(cont[x])+' '+binascii.b2a_hex(cont[x+1])+' '
                            #y=y+1
                            '''
                            showchar+=' '+charb2a[2*x:2*x+2]+' '
                            showchar+=charb2a[2*(x+1):2*(x+1)+2]+' '                          
                        temp=0
                        x=x+2
                    elif (x+2<clen) and calc.needChange(cont[x+2]):
                    #elif (x+2<clen) and need_change_list[int(charb2a[2*(x+2):2*(x+2)+2])]:
                        if temp:
                            '''
                            showchar+=cont[x]+cont[x+1]
                            showchar+=' '+binascii.b2a_hex(cont[x+2])+' '
                            #showchar.append(cont[x]+cont[x+1])
                            #showchar[y]=cont[x]+cont[x+1]+' '+binascii.b2a_hex(cont[x+2])+' '
                            #y=y+1
                            '''
                            showchar+=cont[x]+cont[x+1]
                            showchar+=' '+charb2a[2*(x+2):2*(x+2)+2]+' '
                        else:
                            '''
                            showchar+=binascii.b2a_hex(cont[x])+' '
                            showchar+=binascii.b2a_hex(cont[x+1])+' '
                            showchar+=binascii.b2a_hex(cont[x+2])+' '
                            #showchar.append(binascii.b2a_hex(cont[x])+' ')
                            #showchar.append(binascii.b2a_hex(cont[x+1])+' ')
                            #showchar[y]=binascii.b2a_hex(cont[x])+' '+binascii.b2a_hex(cont[x+1])+' '+binascii.b2a_hex(cont[x+2])+' '
                            #y=y+1
                            '''
                            showchar+=charb2a[2*x:2*x+2]+' '
                            showchar+=charb2a[2*(x+1):2*(x+1)+2]+' '
                            showchar+=charb2a[2*(x+2):2*(x+2)+2]+' '
                        temp=0
                        x=x+3
                    else:
                        if x+2<clen:
                            '''
                            showchar+=cont[x]+cont[x+1]+cont[x+2]
                            #showchar[y]=cont[x]+cont[x+1]+cont[x+2]
                            #y=y+1
                            '''
                            showchar+=cont[x]+cont[x+1]+cont[x+2]
                            temp=1
                            x=x+3
                        elif x+1<clen:
                            if temp:
                                '''
                                showchar+=cont[x]+cont[x+1]
                                #showchar[y]=cont[x]+cont[x+1]
                                #y=y+1
                                '''
                                showchar+=cont[x]+cont[x+1]
                                temp=1
                            else:
                                '''
                                showchar+=binascii.b2a_hex(cont[x])+' '
                                showchar+=binascii.b2a_hex(cont[x+1])+' '
                                #showchar.append(binascii.b2a_hex(cont[x])+' ')
                                #showchar[y]=binascii.b2a_hex(cont[x])+' '+binascii.b2a_hex(cont[x+1])+' '
                                #y=y+1
                                '''
                                showchar+=charb2a[2*x:2*x+2]+' '
                                showchar+=charb2a[2*(x+1):2*(x+1)+2]+' '
                            x=x+2
                        else:
                            if temp:
                                '''
                                showchar+=cont[x]
                                #showchar[y]=cont[x]
                                #y=y+1
                                '''
                                showchar+=cont[x]
                                temp=1
                            else:
                                '''
                                showchar+=binascii.b2a_hex(cont[x])+' '
                                #showchar[y]=binascii.b2a_hex(cont[x])+' '
                                #y=y+1
                                '''
                                showchar+=charb2a[2*x:2*x+2]+' '
                            x=x+1
            showchar=showchar.replace('\r\n','<br />')
            showcontent.append(showchar)
            #showcontent.append(''.join(showchar).replace('\r\n','<br />'))
        realnode['showcontent']=showcontent

def getsig(node,pre_L5node):
    for key, stream in node.items():
        #if stream.has_key('session'):
        if 'session' in stream:
            realnode=stream['session']
            #if .has_key(key):
            if key in pre_L5node:
                node[key]['addsize']=node[key]['size']-pre_L5node[key]['size']
            else:
                node[key]['addsize']=node[key]['size']
            #print key,node[key]['addsize']
        else:
            realnode=stream

        packetnum=len(realnode['content'])

        if 1:
            for checknum in xrange(0,packetnum):
                if realnode['content'][checknum][0:4] not in var.rule:
                    calc.compare(realnode,packetnum)
                    #if (not stream.has_key('session')) and (None not in realnode['canalysis']['sig'][0:2]) and \
                    if ('session' not in stream) and (None not in realnode['canalysis']['sig'][0:2]) and \
                       '\x00\x00' !=''.join(realnode['canalysis']['sig'][0:2]).replace('^','').replace('~',''):
                        realnode['canalysis']['headSig']=''.join(realnode['canalysis']['sig'][0:2]).replace('^','')
                    #if (not stream.has_key('session')) and (None not in realnode['canalysis']['sig'][-2:]) and \
                    if ('session' not in stream) and (None not in realnode['canalysis']['sig'][-2:]) and \
                       '\x00\x00' !=''.join(realnode['canalysis']['sig'][-2:]).replace('^','').replace('~',''):
                        realnode['canalysis']['tailSig']=''.join(realnode['canalysis']['sig'][-2:]).replace('^','').replace('~','')
                        #print realnode['canalysis']['tailSig']
                    break
                if checknum==packetnum-1:
                    #if stream.has_key('session'):
                    if 'session' in stream:
                        calc.http(realnode,packetnum,0)
                    else:
                        calc.http(realnode,packetnum,1)

        showchar=""
        judge=""
        for x in realnode['canalysis']['sig'][0:4]:
            if x:
                judge+=x
        judge=judge.replace('~','').replace('^','')
        #print judge
        if judge in var.rule or judge[-3:] in var.rule or re.match('^[a-zA-Z][a-zA-Z ]{3}',judge):
            markNone=0
            for char in realnode['canalysis']['sig']:
                if markNone<5:
                    if char:
                        markNone=0
                        if len(char)==1:
                            if calc.needChange(char):
                                showchar+=binascii.b2a_hex(char)+' '
                            else:
                                showchar+=char
                        elif len(char)==2 and char[1]=='$':
                            if calc.needChange(char[0]):
                                showchar=showchar+binascii.b2a_hex(char[0])
                            else:
                                showchar+=char[0:-1]
                        elif len(char)==3 and char[0:2]=='.*':
                            if calc.needChange(char[2]):
                                showchar=showchar+char[0:2]+binascii.b2a_hex(char[2])+' '
                            else:
                                showchar+=char
                        elif len(char)==4 and char[0:2]=='.*' and char[3]=='$':
                            if calc.needChange(char[2]):
                                showchar=showchar+char[0:2]+binascii.b2a_hex(char[2])
                            else:
                                showchar+=char[0:-1]
                        elif re.match('^\[.*\]$',char) or re.match('^<.*>$',char):
                            showchar+=char
                    else:
                        showchar+='.'
                        markNone+=1
                else:
                    if char:
                        showchar=showchar[0:-4]+'{'+str(markNone)+'}'
                        markNone=0
                        if len(char)==1:
                            if calc.needChange(char):
                                showchar+=binascii.b2a_hex(char)+' '
                            else:
                                showchar+=char
                        elif len(char)==2 and char[1]=='$':
                            if calc.needChange(char[0]):
                                showchar=showchar+binascii.b2a_hex(char[0])
                            else:
                                showchar+=char[0:-1]
                        elif len(char)==3 and char[0:2]=='.*':
                            if calc.needChange(char[2]):
                                showchar=showchar+char[0:2]+binascii.b2a_hex(char[2])+' '
                            else:
                                showchar+=char
                        elif len(char)==4 and char[0:2]=='.*' and char[3]=='$':
                            if calc.needChange(char[2]):
                                showchar=showchar+char[0:2]+binascii.b2a_hex(char[2])
                            else:
                                showchar+=char[0:-1]
                        elif re.match('^\[.*\]$',char) or re.match('^<.*>$',char):
                            showchar+=char
                    else:
                        markNone+=1                    
            if markNone>=5:
                showchar=showchar[0:-4]+'{'+str(markNone)+'}'
            temp=showchar.replace('~','').replace('^','')
            while temp[-2:]=='\r\n':
                temp=temp[0:-2]
            realnode['canalysis']['showsig']=temp.replace('\n','<br />')
        else:
            markNone=0
            for char in realnode['canalysis']['sig']:
                if markNone<5:
                    if char:
                        markNone=0
                        if len(char)==1:
                            showchar+=binascii.b2a_hex(char)+' '
                        elif len(char)==2 and char[1]=='$':
                            showchar=showchar+binascii.b2a_hex(char[0])+char[1]
                        elif len(char)==3 and char[0:2]=='.*':
                            showchar=showchar+char[0:2]+binascii.b2a_hex(char[2])+' '
                        elif len(char)==4 and char[0:2]=='.*' and char[3]=='$':
                            showchar=showchar+char[0:2]+binascii.b2a_hex(char[2])+char[3]
                    else:
                        showchar+='.'
                        markNone+=1
                else:
                    if char:
                        #by zhuzhu in 20150926滑动
                        if len(char)==2 and char[1]=='$':
                            showchar=showchar[0:-5]
                        elif len(char)==3 and char[0:2]=='.*':
                            showchar=showchar[0:-5]
                        elif len(char)==4 and char[0:2]=='.*' and char[3]=='$':
                            showchar=showchar[0:-5]
                        else:
                            showchar=showchar[0:-4]+'{'+str(markNone)+'}'
                        markNone=0
                        if len(char)==1:
                            showchar+=binascii.b2a_hex(char)+' '
                        elif len(char)==2 and char[1]=='$':
                            showchar=showchar+binascii.b2a_hex(char[0])+char[1]
                        elif len(char)==3 and char[0:2]=='.*':
                            showchar=showchar+char[0:2]+binascii.b2a_hex(char[2])+' '
                        elif len(char)==4 and char[0:2]=='.*' and char[3]=='$':
                            showchar=showchar+char[0:2]+binascii.b2a_hex(char[2])+char[3]
                    else:
                        markNone+=1
            if markNone>=5:
                showchar=showchar[0:-4]+'{'+str(markNone)+'}'

            myShow=[]
            mybz=0
            for myc in realnode['canalysis']['sig']:
                if myc==None:
                    myShow.append('.')
                elif len(myc)==1 and calc.needChange(myc):
                    myShow.append('.')
                #因为存在.*\x9c这种情况
                elif len(myc)==2 and calc.needChange(myc[0]):
                    myShow.append('.$')
                elif len(myc)==3 and calc.needChange(myc[2]):
                    myShow.append('.*.')
                elif len(myc)==4 and calc.needChange(myc[2]):
                    myShow.append('.*.$')
                else:
                    myShow.append(myc)
                    mybz=1
            #不要显示全部为.........的情况
            if mybz==0:
                myStr=''
            else:
                myStr='<br />'+''.join(myShow)
            realnode['canalysis']['showsig']=showchar+myStr
        #print time.time()
            
if __name__=="__main__":
    #pdb.set_trace()
    L5node = {}
    L3node={}
    synnode={}
    errornode={}
    spnum=8
    scnum=1
    pname=r'C:\all.pcap'
    nFilter={}
    f = file(r'C:\all.pcap',"rb")
    
    pcap = dpkt.pcap.Reader(f)

    profile.run("get_node(pcap,L5node,L3node,synnode,errornode,spnum,scnum,pname,nFilter)")

