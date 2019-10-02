#! /usr/bin/env python
# -*- coding: utf-8 -*-
'''
@author zhuzhu
@contact QQ327909056
'''

import sys,re
import var
    
def needChange(char):
    '''
    if ('\x00'<=char<='\x19' and char not in ['\x0a','\x0d']) or char>='\x7f' or char in ['\x3c','\x3e']:
        return True
    else:
        return False
    '''
    #做数组尝试优化失败，因为字符转整数有损耗相抵
    if ('\x19'<char<'\x7f' and char != '\x3c' and char !='\x3e') or char=='\x0a' or char=='\x0d':
        return False
    else:
        return True
    
def disContinue(olist):
    olen=len(olist)-1
    for x in xrange(0,olen):
        if olist[x] is not None and olist[x+1] is not None:
            return False
    return True

def str_have_kw(ostr,kwlist):
    for x in kwlist:
        if x in ostr:
            return True
    return False

def alist_have_str(ostr,alist):
    i=0
    for x in alist:
        if re.match(ostr,x):
            i+=1
    if float(i)/len(alist)>0.6:
        return True
    else:
        return False

def list_to_str(olist):
    ostr=''
    for x in olist:
        if x:
            if x in ['_','^_','~_']:
                ostr+='@'
            elif x in ['-','^-','~-']:
                ostr+='$'
            else:
                ostr+=x
        else:
            ostr+='#'
    return ostr

def newL3key(keylist,M,status):
    atr=[]
    port=[]
    atr_port=[]
    ip=[]
    num=0
    for key in keylist:
        leave=key.split('_')
        ip.append(leave[1])
        atr_port.append(leave[0]+'_'+leave[2])
    if len(set(ip))==1:
        status=ip[0]+status
    atr_port=list(set(atr_port))
    for key in atr_port:
        leave=key.split('_')
        atr.append(leave[0])
        if ' ' in leave[1]:
            nleave=leave[1].split(' ')
            if '<' in nleave[1]:
                #print nleave
                port.append(nleave[0])
                port.append(nleave[2])
                num+=int(nleave[1][1:-1])-2
            else:
                port=port+nleave  
        else:
            port.append(leave[1])
    if atr.count(atr[0])==len(atr):
        newkey=atr[0]+'_'+status+str(M)
        port=list(set(port))
        for x in xrange(0,len(port)):
            port[x]=int(port[x])
        port.sort()
        if len(port)>3:
            newkey+='_'+str(min(port))+' '+'<'+str(len(port)+num)+'>'+' '+str(max(port))
        else:
            for x in xrange(0,len(port)):
                port[x]=str(port[x])
            newkey+='_'+' '.join(port)
    else:
        newkey=' '.join(atr)+'_'+status+str(M)+'_'+' '.join(port)

    return newkey

def newLeavekey(keylist):
    leaveSub=[]
    #print keylist
    for key in keylist:
        #print key
        leaveSub.append([key.split('-')[1],int(key.split('-')[2])])
    return leaveSub

def cflow(size):
    if size >= 1024*1024*1024:
        value=str(float("%.2f" %(float(size)/(1024*1024*1024))))+'GB'
    elif size >=1024*1024:
        value=str(float("%.2f" %(float(size)/(1024*1024))))+'MB'
    elif size >=1024:
        value=str(float("%.2f" %(float(size)/1024)))+'KB'
    else:
        value=str(size)+'B'
    return value

def get_start(sig):
    start=0
    slen=len(sig)
    #连续两个非空
    for i in xrange(0,slen):
        #00 00的情况，也不能作为固定特征
        if i+1 < slen and sig[i] == chr(0) and sig[i+1] == chr(0):
            continue
        elif i+1 < slen and sig[i] != None and sig[i+1] != None:
            start=i+2

    return start

#不止一个包并且长度不相等时调用
def reverse_match(pl,content,packetnum):
    minlength=min(pl)
    sig=[]
    ct=[]
    for x in xrange(0,packetnum):
        ct.append(list(content[x]))
        ct[x].reverse()

    IsOver=False
    for y in xrange(0,minlength):
        for z in xrange(1,packetnum):
        #for z in xrange(0,packetnum):
            if ct[0][y]!=ct[z][y]:
                IsOver=True
                break
            elif z==packetnum-1:
                sig.append(ct[0][y])
        if IsOver:
            break
    sig.reverse()
    return sig

#固定位置
def fixed_match(pl,content,packetnum):
    sig=[]
    minlength=min(pl)

    for y in xrange(0,minlength):
        for z in xrange(1,packetnum):
        #for z in xrange(0,packetnum):
            if content[0][y]!=content[z][y]:
                sig.append(None)
                break
            elif z==packetnum-1:
                sig.append(content[0][y])

    return sig

#滑动位置
def slide_match(pl,content,packetnum,sig,rsig):
    real_len=len(sig)
    sig_len=real_len-len(rsig)
    start=get_start(sig)
    if rsig!=[]:
        rsig[0]='.*'+rsig[0]
        rsig[-1]=rsig[-1]+'$'
        newsig=sig[0:sig_len]+rsig
    else:
        newsig=sig
    #没有可以滑动的
    if start >= sig_len:
        return newsig
    loc=pl.index(real_len)
    #没有找到，此时出现异常，退出
    if loc==-1:
        return newsig
    cnt=content[loc]
    #通过设置结束位置，可以跳过一些子串，只需要最长即可
    result=[]
    End=0
    for i in xrange(start,sig_len):
        #当没有找到串时，设置遍历结束位置
        if End < i+1:
            End = i+1
        #下面的可以显示1位特征
        '''
        if End < i:
            End = i
        '''
        for j in xrange(sig_len,End,-1):
            Ismatch=False
            keyword=cnt[i:j]
            for z in xrange(0,packetnum):
                if keyword not in content[z][start:sig_len]:
                    break
                elif z==packetnum-1:
                    Ismatch=True
            if Ismatch:
                #记录
                result.append([i,j,j-i])
                #遍历到j即可
                End=j;
                #退出这行
                break
    #对单个字符造成的干扰，插除
    if result!=[]:
        for x in xrange(start,sig_len):
            newsig[x]=None
    else:
        return newsig
    #冲突处理，按长度从大到小排序，长度大的优先级高
    result.sort(key=lambda x:x[2],reverse=True)
    rlen=len(result)

    for x in xrange(0,rlen):
        if x!=0:
            #需要遍历所有的不在此区域才可以
            for w in xrange(0,x):
                if (result[w][0]<=result[x][0]<result[w][1] or result[w][0]<result[x][1]<=result[w][1]):
                    break
                #暂时方法，被包含就去掉，这个其实不科学，科学做法应该记录各自位置，处理冲突
                elif cnt[result[x][0]:result[x][1]] in cnt[result[w][0]:result[w][1]]:
                    break
                elif w==x-1:
                    for y in xrange(result[x][0],result[x][1]):
                        if y == result[x][0]:
                            newsig[y]='.*'+cnt[y]
                        else:
                            newsig[y]=cnt[y]
        else:
            for y in xrange(result[x][0],result[x][1]):
                if y == result[x][0]:
                    newsig[y]='.*'+cnt[y]
                else:
                    newsig[y]=cnt[y]

    #为了不显示..*，在此做一下处理
    ret_sig=newsig[0:start]
    for x in xrange(start,real_len):
            if newsig[x] is not None:
                ret_sig.append(newsig[x])
        
    return ret_sig
                

def str_match(pl,content,packetnum,mType):
    #只有一个包
    if packetnum==1:
        sig=list(content[0][0:])
        return sig
    sig=fixed_match(pl,content,packetnum)
    #报长是否一致
    if mType=='CNT':
        if len(set(pl))==1:
            return sig
    rsig=reverse_match(pl,content,packetnum)
    sig=slide_match(pl,content,packetnum,sig,rsig)

    return sig
    
def compare(realnode,packetnum):
    sig=str_match(realnode['pl'],realnode['content'],packetnum,'CNT')
    realnode['canalysis']={}
    if len(sig)==sig.count(None):
        pType='EP'
    else:
        pType='NEP'
    realnode['canalysis']['quality']=pType
    realnode['canalysis']['sig']=sig    


def http(realnode,packetnum,need):
    httpdict={}
    for x in xrange(0,packetnum):
        templist=realnode['content'][x].split('\r\n')
        while templist[-1]=='':
            del templist[-1]
        tlen=len(templist)
        for y in xrange(0,tlen):
            temp=templist[y]
            #if temp!='' or y!=len(templist)-1:
            if True:
                if y==0:
                    kw=temp[0:4]
                    style=kw
                elif (len(temp.split(':',1))==1 or not re.match('^[a-zA-Z][a-zA-Z-_]',temp)) and not re.match('^[0-9a-zA-Z-_.]{5}',temp) and temp!='':
                    kw='other'
                    plen=0
                    for z in templist[y:]:
                        plen+=len(z)
                    #if httpdict.has_key(kw):
                    if kw in httpdict:
                        httpdict[kw]['content'].append(''.join(templist[y:]))
                        httpdict[kw]['pl'].append(plen)
                        httpdict[kw]['location'].append(y)
                    else: 
                        httpdict[kw]={}
                        httpdict[kw]['content']=[''.join(templist[y:])]
                        httpdict[kw]['pl']=[plen]
                        httpdict[kw]['location']=[y]
                    break
                else:
                    kw=temp.split(':',1)[0]
            
                #if httpdict.has_key(kw):
                if kw in httpdict:
                    httpdict[kw]['content'].append(temp)
                    httpdict[kw]['pl'].append(len(temp))
                    httpdict[kw]['location'].append(y)
                else:
                    httpdict[kw]={}
                    httpdict[kw]['content']=[temp]
                    httpdict[kw]['pl']=[len(temp)]
                    httpdict[kw]['location']=[y]
            else:
                continue
    
    printlist=[]
    for key in httpdict:
        printlist.append([min(httpdict[key]['location']),key])
        if len(httpdict[key]['pl'])==1:
            httpdict[key]['canalysis']={}
            httpdict[key]['canalysis']['quality']='--'
            httpdict[key]['canalysis']['sig']=list(httpdict[key]['content'][0])
        else:
            compare(httpdict[key],len(httpdict[key]['pl']))   
    printlist.sort()
    sig=[]
    for temp in printlist:
        key=temp[1]
        #pdb.set_trace()
        if len(httpdict[key]['location'])==packetnum:
            status='[A]'
        else:
            status='['+str(len(httpdict[key]['location']))+']'

        
        if key in var.show:
            sig=sig+[status]+httpdict[key]['canalysis']['sig']+[str(list(set(httpdict[key]['location'])))]+['\r','\n']
        elif key in ['POST','HEAD']:
            sig=sig+['<span style="color:#000080">']+[status]+httpdict[key]['canalysis']['sig']+[str(list(set(httpdict[key]['location'])))]+['<br /></span>']
        elif key=='Accept' and re.match('Accept:\*/\*',list_to_str(httpdict[key]['canalysis']['sig']).replace('~','').replace('^','')):
            sig=sig+['<span style="color:#528B8B">']+[status]+httpdict[key]['canalysis']['sig']+[str(list(set(httpdict[key]['location'])))]+['<br /></span>']
        elif key=='Host' and re.match('Host:.*[a-zA-Z]',list_to_str(httpdict[key]['canalysis']['sig']).replace('~','').replace('^','')):
            sig=sig+['<span style="color:#B03060">']+[status]+httpdict[key]['canalysis']['sig']+[str(list(set(httpdict[key]['location'])))]+['<br /></span>']
        elif key=='User-Agent' and not re.match(var.BUA,list_to_str(httpdict[key]['canalysis']['sig']).replace('~','').replace('^','')) \
             and None not in httpdict[key]['canalysis']['sig'] \
             and len(httpdict[key]['canalysis']['sig'])!=12:
            sig=sig+['<span style="color:#0000EE">']+[status]+httpdict[key]['canalysis']['sig']+[str(list(set(httpdict[key]['location'])))]+['<br /></span>']
        elif key=='Range':
            sig=sig+['<span style="color:#7A7A7A">']+[status]+httpdict[key]['canalysis']['sig']+[str(list(set(httpdict[key]['location'])))]+['<br /></span>']
        elif key=='Type':
            sig=sig+['<span style="color:#CD00CD">']+[status]+httpdict[key]['canalysis']['sig']+[str(list(set(httpdict[key]['location'])))]+['<br /></span>']
        elif key=='other':
            sig=sig+['<span style="color:#458B00">']+[status]+httpdict[key]['canalysis']['sig']+[str(list(set(httpdict[key]['location'])))]+['<br /></span>'] 
        else:
            sig=sig+['<span style="display:none;color:#EE0000" class="unshow">']+[status]+httpdict[key]['canalysis']['sig']+[str(list(set(httpdict[key]['location'])))]+['<br /></span>']  #+['\r','\n']
        
        
    realnode['canalysis']={}
    realnode['canalysis']['quality']='web'
    realnode['canalysis']['sig']=sig
    if not need:
        return
    #print sig
    if 'User-Agent' in httpdict and not re.match(var.BUA,list_to_str(httpdict['User-Agent']['canalysis']['sig']).replace('~','').replace('^',''))\
       and len(httpdict['User-Agent']['location'])==packetnum \
       and None not in httpdict['User-Agent']['canalysis']['sig'] \
       and not re.match('.*CFNetwork',list_to_str(httpdict['User-Agent']['canalysis']['sig']).replace('~','').replace('^',''))\
       and len(httpdict['User-Agent']['canalysis']['sig'])!=12:
        realnode['canalysis']['uaSig']=style+list_to_str(httpdict['User-Agent']['canalysis']['sig']).replace('~','').replace('^','')
        #print realnode['canalysis']['uaSig']
    if 'other' in httpdict and len(httpdict['other']['canalysis']['sig'])>=2\
       and len(httpdict['other']['location'])==packetnum:
        realnode['canalysis']['otherSig']=style+list_to_str(httpdict['other']['canalysis']['sig'][0:2]).replace('~','').replace('^','')
    if 'Host' in httpdict and len(httpdict['Host']['location'])==packetnum and \
       (re.match('Host:.*[a-zA-Z]',list_to_str(httpdict['Host']['canalysis']['sig']).replace('~','').replace('^','')) or \
        re.match('Host: [0-9\.]*',list_to_str(httpdict['Host']['canalysis']['sig']).replace('~','').replace('^','')) ):
        hoststr=list_to_str(httpdict['Host']['canalysis']['sig'][6:]).replace('~','').replace('^','')
        if re.match('Host:.*[a-zA-Z]',list_to_str(httpdict['Host']['canalysis']['sig']).replace('~','').replace('^','')):
            if style=='POST':
                if '.com.cn' in hoststr:
                    realnode['canalysis']['hostSig']=style+'.'.join(hoststr.split('.')[-3:])
                    host2='.'.join(hoststr.split('.')[-3:])
                else:
                    realnode['canalysis']['hostSig']=style+'.'.join(hoststr.split('.')[-2:])
                    host2='.'.join(hoststr.split('.')[-2:])
            else:
                if '.com.cn' in hoststr:
                    realnode['canalysis']['hostSig']=style+'.'.join(hoststr.split('.')[-4:])
                    host2='.'.join(hoststr.split('.')[-3:])
                else:
                    realnode['canalysis']['hostSig']=style+'.'.join(hoststr.split('.')[-3:])
                    host2='.'.join(hoststr.split('.')[-2:])
        else:
            host2='****'
        #print realnode['canalysis']['hostSig']
        if re.match('^[a-zA-Z]+ /[^#]+/',list_to_str(httpdict[style]['canalysis']['sig']).replace('~','').replace('^','')):
            getstr=list_to_str(httpdict[style]['canalysis']['sig']).replace('~','').replace('^','').split('/')[0]\
                    +list_to_str(httpdict[style]['canalysis']['sig']).replace('~','').replace('^','').split('/')[1]+host2
            realnode['canalysis']['headSig']=getstr
            #print getstr
        #print realnode['canalysis']['headSig']
        if '.' in httpdict[style]['canalysis']['sig'] or \
           '~.' in httpdict[style]['canalysis']['sig'] or\
           '^.' in httpdict[style]['canalysis']['sig']:
            tail=list_to_str(httpdict[style]['canalysis']['sig']).replace('~','').replace('^','').split('.')
            if len(tail)>=2:
                if re.match(var.BTL,list_to_str(httpdict[style]['canalysis']['sig']).replace('~','').replace('^','')) or alist_have_str(var.BTL,httpdict[style]['content']):
                    stail='OrdinaryWebBrowsing'
                elif re.match(var.BQLM,list_to_str(httpdict[style]['canalysis']['sig']).replace('~','').replace('^','')) or alist_have_str(var.BQLM,httpdict[style]['content']):
                    stail='OrdinaryWebRequirM'
                elif re.match(var.BQLS,list_to_str(httpdict[style]['canalysis']['sig']).replace('~','').replace('^','')) or alist_have_str(var.BQLS,httpdict[style]['content']):
                    stail='OrdinaryWebRequirS'
                else:
                    stail=tail[-2]
                realnode['canalysis']['tailSig']=style+stail+host2
                #print realnode['canalysis']['tailSig']
    
        
    

    


    
