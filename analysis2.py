#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
@author zhuzhu
@contact QQ327909056
'''
import getopt, sys, os,time
import hashlib,binascii
import dpcap,calc,var
import json,re
import pdb
import profile

def richNode(L5node,L3node,errornode,pre_L5node):
    totalflow=0
    for key, stream in L5node.items():
        totalflow+=stream['size']
    for key, stream in L5node.items():
        size=stream['size']
        rate=str(((size*1000)/totalflow)/10.0)+'%'+'['+str(calc.cflow(stream['addsize']))+']'
        split=key.split('_')
        skey='S'+split[4]+'_'+split[0]+'_'+split[1]
        dkey='D'+split[4]+'_'+split[2]+'_'+split[3]
        #if stream.has_key('newkey'):
        if 'newkey' in stream:
            skey+='_'+stream['newkey'].split('_')[5]+'_'+stream['newkey'].split('_')[6]+'_'+stream['newkey'].split('_')[7]
            dkey+='_'+stream['newkey'].split('_')[5]+'_'+stream['newkey'].split('_')[6]+'_'+stream['newkey'].split('_')[7]
        #if stream.has_key('ssl'):
        if 'ssl' in stream:
            skey+='_'+stream['ssl'].split('_')[5]
            dkey+='_'+stream['ssl'].split('_')[5]
        if len(L3node[skey]['pl'])==1:
            del L3node[skey]
            subNode(L3node,dkey,L5node,key,size,rate)
        elif len(L3node[dkey]['pl'])==1:
            del L3node[dkey]
            subNode(L3node,skey,L5node,key,size,rate)
        elif len(L3node[skey]['pl'])>len(L3node[dkey]['pl']):
            #del L3node[dkey]
            subNode(L3node,skey,L5node,key,size,rate)
        else:
            #del L3node[skey]
            subNode(L3node,dkey,L5node,key,size,rate)
    for key, stream in L3node.items():
        if stream['sub']==[]:
            del L3node[key]
            continue
        if len(stream['sub'])!=len(stream['pl']):
            L3node[key]['pl']=[]
            L3node[key]['content']=[]
            L3node[key]['size']=0
            for sub in stream['sub']:
                L3node[key]['pl'].append(sub[13])
                L3node[key]['content'].append(sub[12])
                L3node[key]['size']+=sub[11]
        L3node[key]['addsize']=0
        for sub in stream['sub']:
            L3node[key]['addsize']+=sub[17]
        #print key,L3node[key]['addsize']
    dpcap.getsig(L3node,pre_L5node)
    return L3node,totalflow    

def nodeBI(L3node,totalflow):
    interval=64
    for key, stream in L3node.items():
        stream['rate']=str(((stream['size']*1000)/totalflow)/10.0)+'%'+'['+str(calc.cflow(stream['addsize']))+']'
        spl=[]
        apl=[[] for x in xrange(var.maxpl)]
        showapl=''
        showsig=''
        for sub in stream['sub']:
            if len(sub[10]) == var.maxpl:
                spl.append(sub[10])
            for x in xrange(0,len(sub[10])):
                apl[x].append(sub[10][x])
        IsOrder=True
        for x in xrange(0,len(apl)):
            if apl[x]==[]:
                break
            apl[x]=list(set(apl[x]))
            apl[x].sort()
            if x!=len(apl):
                showapl+=str(apl[x])
            if IsOrder == False:
                continue
            alen=len(apl[x])
            if alen == 1:
                showsig+=str(apl[x][0])+' '
            elif len(set([ type(y) for y in apl[x] ])) != 1:
                #showsig+='.'
                IsOrder = False
            elif type(apl[x][0])==int:
                if apl[x][-1]-apl[x][0]>interval:
                    showsig+='.'
                else:
                    showsig+=str(apl[x][0])+'<>'+str(apl[x][-1])+' '
            else:
                temp=[int(y) for y in apl[x]]
                temp.sort()
                if temp[-1]-temp[0]>interval:
                    showsig+='.'
                else:
                    showsig+=str(temp[0])+'<>'+str(temp[-1])+' '
        stream['banalysis']={}
        stream['banalysis']['sig']=apl
        stream['banalysis']['showsig']=showapl+'<br />'+showsig

    return L3node,totalflow

def autoFilter(L3node,totalflow):
    pass
    return L3node,totalflow

def subNode(L3node,L3key,L5node,L5key,size,rate):
    if L3key.split('_')[0][0]=='S':
        ip=L5key.split('_')[2]
        port=L5key.split('_')[3]
        son=u'目的'
    else:
        ip=L5key.split('_')[0]
        port=L5key.split('_')[1]
        son=u'源端'
    #增加TCP|UDP属性，增加时间戳
    son+=L5key.split('_')[4]
    
    L3node[L3key]['size']+=size
    pnum=len(L5node[L5key]['session']['pl'])
    if pnum==1 or L5node[L5key]['session']['canalysis']['quality']=='web':
        linshi=L5node[L5key]['session']['showcontent'][0]
        if linshi[0:3]=='GET':
            if linshi[-18:]=="<br /><br /><br />":
                linshi=linshi[:-12]
            elif linshi[-12:]=="<br /><br />":
                linshi=linshi[:-6]
            elif linshi[-6:]!="<br />":
                linshi=linshi+'<br />'
            try:
                L5ContentSig=linshi+"<a target='_blank' style='color:red' href='http://"+linshi.split('Host: ')[1].split('<br />')[0]+linshi.split(' ')[1]+u"'>访问</a>"
            except:
                L5ContentSig=linshi
        else:
            L5ContentSig=linshi
        CorS='C'
    else:
        linshi=L5node[L5key]['session']['showcontent'][0]
        if linshi[0:3]=='GET':
            try:
                L5ContentSig=linshi+'<br /><span style="color:red">'+L5node[L5key]['session']['canalysis']['showsig']+'</span>'+"<br /><a target='_blank' style='color:red' href='http://"+linshi.split('Host: ')[1].split('<br />')[0]+linshi.split(' ')[1]+u"'>访问</a>"
            except:
                L5ContentSig=linshi+'<br /><span style="color:red">'+L5node[L5key]['session']['canalysis']['showsig']+'</span>'
        else:
            L5ContentSig=linshi+'<br /><span style="color:red">'+L5node[L5key]['session']['canalysis']['showsig']+'</span>'
        CorS='S'
    L3node[L3key]['sub'].append([son,rate,'1','--',L5node[L5key]['session']['pl'][0],\
                                 '--',ip,int(port),CorS,L5ContentSig,\
                                 L5node[L5key]['apl'],size,L5node[L5key]['session']['content'][0],L5node[L5key]['session']['pl'][0],L3key,\
                                 L5node[L5key]['pname']+'_'+L5key,L5node[L5key]['time'],L5node[L5key]['addsize'],L5node[L5key]['protocol'] ])    
def autoMerger(L3node,totalflow,pre_L5node):
    #[1]:WEB-AHnode:Atr+Host
    AUnode={}
    newnode={}
    A=1
    for key, stream in L3node.items():
        #if stream['canalysis']['quality']=='web' and stream['canalysis'].has_key('hostSig'):
        if stream['canalysis']['quality']=='web' and 'hostSig' in stream['canalysis']:
            subkey=key.split('_')[0]+'_'+stream['canalysis']['hostSig']
            #if AUnode.has_key(subkey):
            if subkey in AUnode:
                AUnode[subkey].append(key)
            else:
                AUnode[subkey]=[key]
    for key in AUnode:
        if len(AUnode[key])!=1:
            newkey=calc.newL3key(AUnode[key],A,'AMHost')
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in AUnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)

    
    #[2]:WEB-AOnode:Atr+Other
    AUnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        #if stream['canalysis']['quality']=='web' and stream['canalysis'].has_key('otherSig'):
        if stream['canalysis']['quality']=='web' and 'otherSig' in stream['canalysis']:
            subkey=key.split('_')[0]+'_'+stream['canalysis']['otherSig']
            #if AUnode.has_key(subkey):
            if subkey in AUnode:
                AUnode[subkey].append(key)
            else:
                AUnode[subkey]=[key]
    for key in AUnode:
        if len(AUnode[key])!=1:
            newkey=calc.newL3key(AUnode[key],A,'AMOther')
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in AUnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)    
   
    #[3]ALPnode:Atr+MinLength+port
    ALPnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        if stream['canalysis']['quality']!='web':
            subkey=key.split('_')[0]+'_'+str(min(stream['pl']))+'_'+key.split('_')[2]
            #if ALPnode.has_key(subkey):
            if subkey in ALPnode:
                ALPnode[subkey].append(key)
            else:
                ALPnode[subkey]=[key]
    for key in ALPnode:
        if len(ALPnode[key])!=1:
            newkey=key.split('_')[0]+'_'+'AMlenP'+str(A)+'_'+key.split('_')[2]
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in ALPnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)
    
    #[4]ALPnode:Atr+port+headcontent2(0-1)
    ALPnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        #if stream['canalysis'].has_key('headSig'):
        if 'headSig' in stream['canalysis']:
            subkey=key.split('_')[0]+'_'+stream['canalysis']['headSig']+'_'+key.split('_')[2]
            #if ALPnode.has_key(subkey):
            if subkey in ALPnode:
                ALPnode[subkey].append(key)
            else:
                ALPnode[subkey]=[key]
    for key in ALPnode:
        if len(ALPnode[key])!=1:
            newkey=key.split('_')[0]+'_'+'AMPortHC'+str(A)+'_'+key.split('_')[2]
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in ALPnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)
    
    #[5]ALPnode:Atr+port+tailcontent2(0-1)
    ALPnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        #if stream['canalysis'].has_key('tailSig'):
        if 'tailSig' in stream['canalysis']:
            #print stream['canalysis']['tailSig']
            subkey=key.split('_')[0]+'_'+stream['canalysis']['tailSig']+'_'+key.split('_')[2]
            #if ALPnode.has_key(subkey):
            if subkey in ALPnode:
                ALPnode[subkey].append(key)
            else:
                ALPnode[subkey]=[key]
    for key in ALPnode:
        if len(ALPnode[key])!=1:
            newkey=key.split('_')[0]+'_'+'AMPortTC'+str(A)+'_'+key.split('_')[2]
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in ALPnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)
    
    #[6]ALPnode:Atr+MinLength+headcontent2(0-1)
    ALPnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        #if stream['canalysis'].has_key('headSig'):
        if 'headSig' in stream['canalysis']:
            subkey=key.split('_')[0]+'_'+str(min(stream['pl']))+'_'+stream['canalysis']['headSig']
            #if ALPnode.has_key(subkey):
            if subkey in ALPnode:
                ALPnode[subkey].append(key)
            else:
                ALPnode[subkey]=[key]
    for key in ALPnode:
        if len(ALPnode[key])!=1:
            newkey=calc.newL3key(ALPnode[key],A,'AMLenHC')
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in ALPnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)
    
    #[7]ALPnode:Atr+MinLength+tailcontent2(0-1)
    ALPnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        #if stream['canalysis'].has_key('tailSig'):
        if 'tailSig' in stream['canalysis']:
            subkey=key.split('_')[0]+'_'+str(min(stream['pl']))+'_'+stream['canalysis']['tailSig']
            #if ALPnode.has_key(subkey):
            if subkey in ALPnode:
                ALPnode[subkey].append(key)
            else:
                ALPnode[subkey]=[key]
    for key in ALPnode:
        if len(ALPnode[key])!=1:
            newkey=calc.newL3key(ALPnode[key],A,'AMLenTC')
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in ALPnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)


    #[0]:WEB-AUnode:Atr+UA
    AUnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        #if stream['canalysis']['quality']=='web' and stream['canalysis'].has_key('uaSig'):
        if stream['canalysis']['quality']=='web' and 'uaSig' in stream['canalysis']:
            subkey=key.split('_')[0]+'_'+stream['canalysis']['uaSig']
            #if AUnode.has_key(subkey):
            if subkey in AUnode:
                AUnode[subkey].append(key)
            else:
                AUnode[subkey]=[key]
    for key in AUnode:
        #print key
        #if len(AUnode[key])!=1:
        if 1:
            newkey=calc.newL3key(AUnode[key],A,'AMUA')
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in AUnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    '''
    #因为京东包，GET首相同，UA不同，没有被合并，暂时关闭，待以后发现有异常，再做调整
    for key,stream in newnode.items():
        if stream['canalysis'].has_key('hostSig'):
            del newnode[key]['canalysis']['hostSig']
    '''
    L3node=dict(L3node,**newnode)

       
    #[8]ALPnode:Atr+length
    ALPnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        if stream['canalysis']['quality']!='web':
            spl=list(set(stream['pl']))
            spl.sort()
            subkey=key.split('_')[0]+'_'+str(spl)
            #print subkey
            #if ALPnode.has_key(subkey):
            if subkey in ALPnode:
                ALPnode[subkey].append(key)
            else:
                ALPnode[subkey]=[key]
    for key in ALPnode:
        if len(ALPnode[key])!=1:
            newkey=calc.newL3key(ALPnode[key],A,'AMLen')
            #print newkey
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in ALPnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)
    
    #[9]ALPnode:Atr+MinLength+CNone
    ALPnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        if stream['canalysis']['quality']=='EP':
            subkey=key.split('_')[0]+'_'+str(min(stream['pl']))
            #if ALPnode.has_key(subkey):
            if subkey in ALPnode:
                ALPnode[subkey].append(key)
            else:
                ALPnode[subkey]=[key]
    for key in ALPnode:
        if len(ALPnode[key])!=1:
            newkey=calc.newL3key(ALPnode[key],A,'AMMinL')
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in ALPnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)    

    #[10]ALPnode:Atr+MaxLength+CNone
    ALPnode={}
    newnode={}
    #A=1
    for key, stream in L3node.items():
        if stream['canalysis']['quality']=='EP':
            subkey=key.split('_')[0]+'_'+str(max(stream['pl']))
            #if ALPnode.has_key(subkey):
            if subkey in ALPnode:
                ALPnode[subkey].append(key)
            else:
                ALPnode[subkey]=[key]
    for key in ALPnode:
        if len(ALPnode[key])!=1:
            newkey=calc.newL3key(ALPnode[key],A,'AMMaxL')
            newnode[newkey]={}
            newnode[newkey]['pl']=[]
            newnode[newkey]['content']=[]
            newnode[newkey]['sub']=[]
            newnode[newkey]['size']=0
            newnode[newkey]['time']=[]
            newnode[newkey]['addsize']=0
            for xkey in ALPnode[key]:
                newnode[newkey]['pl']+=L3node[xkey]['pl']
                newnode[newkey]['content']+=L3node[xkey]['content']
                newnode[newkey]['sub']+=L3node[xkey]['sub']
                newnode[newkey]['size']+=L3node[xkey]['size']
                newnode[newkey]['time']+=L3node[xkey]['time']
                newnode[newkey]['addsize']+=L3node[xkey]['addsize']
                del L3node[xkey]
            A+=1
    dpcap.getsig(newnode,pre_L5node)
    L3node=dict(L3node,**newnode)
    
    del newnode
    del ALPnode
    del AUnode
    return L3node,totalflow

def finalNode(files,nFilter,pre_L5node,sig):
    """ pcap paser """
    L5node,L3node,errornode,error = dpcap.mfile(files,nFilter,pre_L5node,sig)
    L3node,totalflow=richNode(L5node,L3node,errornode,pre_L5node)
    L3node,totalflow=autoMerger(L3node,totalflow,pre_L5node)
    L3node,totalflow=autoFilter(L3node,totalflow)
    L3node,totalflow=nodeBI(L3node,totalflow)
    #valid 【0】-没有完整会话；【-1】-没有包文件
    valid=len(L5node)
    if valid==0 and len(files)==0:
        valid=-1
    invalid=len(errornode)
    #del L5node
    del errornode
    #print totalflow,valid,invalid
    return L3node,totalflow,valid,invalid,error,L5node
        
def showNode(L3node,totalflow,valid,invalid,usetime,pcapNum,error,sclass,iclass):
    if error:
        return error+u"<br /><span style='color:red'>信息提醒：包文件读入错误，可能导入包并非是libpcap格式文件，请转化为libpcap格式后再分析或者QQ联系开发者</span>"
    #print time.time()
    #网页浏览[htm|js|css|jpg|png|gif|aspx|php|ico]、DNS[53]、DHCP[67-68]、Netbios[137-139]、SSDP[1900]、智能过滤
    if valid==0:
        return u"<br /><span style='color:red'>信息提醒：包文件没有一条完整会话->继续抓包稍后分析或者重新选择包文件</span>"
    if valid==-1:
        return u"<br /><span style='color:red'>信息提醒：没有选择包文件->请选择包文件</span>"
    summary=[u"<table id='summary'><tr><th>分析包数量</th><th>"+str(pcapNum)+u"</th><th>负载总流量</th><th>"+calc.cflow(totalflow)+u"</th><th>总会话数</th><th>"+str(valid+invalid)+u"</th><th>有效会话数</th><th>"+str(valid)\
             +u"</th><th>错包会话数</th><th>"+str(invalid)+u"</th><th>分析后特征数</th><th>"+str(len(L3node))+u"</th><th>减轻工作量</th><th>"\
             +str(float("%.2f" %((valid+invalid-len(L3node))*100/float(valid+invalid))))+'%'+u"</th><th>分析所用时间</th><th>"+str(float("%.2f" %usetime))\
             +u"秒</th><th>分析模式</th><th>自动归类</th><th>实时分析次数</th><th style='color:red' id='aCount'></th><th>实时分析倒计时[秒]</th><th style='color:red' id='aCountDown'></th>\
</tr></table><table id='report'><thead><tr><th></th><th><input type='checkbox' id='cAll'></th><th>连接建立时间</th><th>属性协议</th><th>流量比例[增加]</th><th>会话数</th><th>首报长度</th><th>首长范围</th>\
<th>IP范围</th><th>端口范围</th><th>特征类型</th><th>协议</th><th> 内容特征 <img class='cArrow' /></th><th>报长特征 <img class='bArrow' /></th></tr></thead>"]


    #print time.time()
    subsizekey={}
    for key, stream in L3node.items():
        if sclass=='fp':
            subkey=key.split('_')[0]+key.split('_')[2]
        elif sclass=='f':
            subkey=stream['size']
        elif sclass=='s':
            subkey=len(stream['pl'])
        elif sclass=='p':
            subkey=int(key.split('_')[2].split('<')[0].split(' ')[0])
        elif sclass=='t':
            subkey=min(stream['time'])
        elif sclass=='r':
            subkey=stream['addsize']

        if iclass=='fp':
            L3node[key]['sub'].sort(key=lambda x:x[10][0],reverse=False)
        elif iclass=='f':
            L3node[key]['sub'].sort(key=lambda x:x[11],reverse=True)
        elif iclass=='p':
            L3node[key]['sub'].sort(key=lambda x:x[7],reverse=False)
        elif iclass=='t':
            L3node[key]['sub'].sort(key=lambda x:x[16],reverse=False)
        elif iclass=='r':
            L3node[key]['sub'].sort(key=lambda x:x[17],reverse=True)

    
        #if subsizekey.has_key(subkey):
        if subkey in subsizekey:
            #subsizekey[subkey].append([min(stream['pl']),key])
            subsizekey[subkey].append([stream['size'],key])
        else:
            #subsizekey[subkey]=[[min(stream['pl']),key]]
            subsizekey[subkey]=[[stream['size'],key]]

    #print time.time()        
    subsizekey=subsizekey.items()
    for every in subsizekey:
        every[1].sort(key=lambda x:x[0],reverse=True)

    if sclass=='fp':
        subsizekey.sort(key=lambda x:x[1][0][0],reverse=True)
    elif sclass=='f':
        subsizekey.sort(reverse=True)
    elif sclass=='s':
        subsizekey.sort(reverse=True)
    elif sclass=='p':
        subsizekey.sort(reverse=False)
    elif sclass=='t':
        subsizekey.sort(reverse=False)
    elif sclass=='r':
        subsizekey.sort(reverse=True)
        '''
        for x in subsizekey:
            print x[0]
        '''
    #print time.time()


    
    for subkey,sizekey in subsizekey:   
        for size,key in sizekey:
            attr=key.split('_')[0]
            if attr[0]=='S':
                attr=u'源端'+attr[1:]
            elif attr[0]=='D':
                attr=u'目的'+attr[1:]
            ip=key.split('_')[1]

            if re.match('^A',ip):
                ip=u'任意'
                #pass
            elif re.match('.*[0-9]A',ip):
                ip=ip.split('A')[0]
            elif re.match('^M',ip):
                ip=u'任意[合并]'
            elif re.match('^L',ip):
                ip=u'任意[分离]'
            elif re.match('.*[0-9]L',ip):
                ip=ip.split('L')[0]+u'[分离]'
            elif re.match('.*[0-9]M',ip):
                ip=ip.split('M')[0]+u'[合并]'

            port=key.split('_')[2]
            pnum=len(L3node[key]['pl'])
            if L3node[key]['pl'].count(L3node[key]['pl'][0])==pnum:
                if pnum==1:
                    status=u'--'
                else:
                    status=u'相等'
                prange=str(L3node[key]['pl'][0])
            else:
                status=u'不等'
                prange=str(min(L3node[key]['pl']))+'-'+str(max(L3node[key]['pl']))
            SC=L3node[key]['canalysis']['quality']
            #if port in var.protocol:
                #SC=var.protocol[port]
            #if nFilter.has_key(port):
                #continue
            if SC=="EP":
                SC=u'报长特征'
            elif SC=="NEP" or SC=="web":
                SC=u'内容特征'
            protocol_range=[]
            for sub in L3node[key]['sub']:
                protocol_range.append(sub[18])
            protocol_range=list(set(protocol_range))
            if len(protocol_range) == 1:
                protocol_name = protocol_range[0]
                #protocol_name = protocol_range[0]
            else:
                protocol_name='['+str(len(protocol_range))+']'
            #print protocol_name
            #print protocol_name.decode('utf-8').encode('gbk').decode('utf-8').encode('gbk')
            #time_range=time.strftime("%Y/%m/%d %H:%M:%S",time.localtime(min(L3node[key]['time'])))+'-'+time.strftime("%Y/%m/%d %H:%M:%S",time.localtime(max(L3node[key]['time'])))
            time_range=time.strftime("%H:%M:%S",time.localtime(min(L3node[key]['time'])))+'-'+time.strftime("%H:%M:%S",time.localtime(max(L3node[key]['time'])))
            summary.append("<tbody class='control'><tr class='node'><td><div class='close'></div></td><td class='choose' ><input type='checkbox' id='"+key+"'></td><td>"+time_range+"</td><td class='fd'>")
            try:
                summary.append(attr+'</td><td>'+L3node[key]['rate']+'</td><td>'+str(len(L3node[key]['pl']))+'</td><td>'+status+'</td><td>'\
                            +prange+'</td><td>'+ip+'</td><td class="fd">'+port+'</td><td>'\
                            +SC+'</td><td>'+protocol_name+'</td><td><div class="csig" onmouseover=$(this).children("span.unshow").show() onmouseout=$(this).children("span.unshow").hide()>'\
                            +L3node[key]['canalysis']['showsig']+'</div></td><td><div class="bsig">'+L3node[key]['banalysis']['showsig']+'</div></td></tr></tbody>')
            except Exception,e:
                print Exception,":",e
            #add sort：通过报长排序，期望获得子节点，解决节点下再区分
            #加入tbody是为了快速显示与隐藏
            summary.append("<tbody class='sub' style='display:none;'>")
            #L3node[key]['sub'].sort(key=lambda x:x[10][0])
            for sub in L3node[key]['sub']:
                SC=sub[8]
                if SC=='C':
                    SC=u'首报内容'
                elif SC=='S':
                    SC=u'首报内容<br />会话特征'
                    
                summary.append("<tr class='session'><td><div class='wireshark' id='"+sub[15]+"' onclick=openPcap(this.id)></div></td><td class='choose_son'><input type='checkbox' id='")
                summary.append(key+'-'+sub[6]+'-'+str(sub[7])+'-'+sub[14]+"'></td>")
                '''
                summary.append('<td>'+sub[0]+'</td><td>'+sub[1]+'</td><td>'+str(sub[2])+'</td><td>'+str(sub[3])+'</td><td>'+str(sub[4])+'</td><td>'\
                               +sub[6]+'</td><td>'+str(sub[7])+'</td><td>'+SC\
                               +'</td><td><div class="csig" onmouseover=$(this).children("span.unshow").show() onmouseout=$(this).children("span.unshow").hide()>'\
                               +sub[9]+'</div></td><td><div class="bsig">'+str(sub[10])+'</div></td></tr>')
                '''
                dlist=sub[15].split('_')
                summary.append('<td>'+time.strftime("%Y/%m/%d %H:%M:%S",time.localtime(sub[16]))+':'+str(repr(sub[16]).split('.')[1])+'</td><td>'+sub[0]+'</td><td>'+sub[1]+'</td><td>'+str(sub[2])+'</td><td>'+str(sub[3])+'</td><td>'+str(sub[4])+'</td><td>'\
                               +(dlist[1]+'-'+dlist[3])+'</td><td>'+(dlist[2]+'-'+dlist[4])+'</td><td>'+SC\
                               +'</td><td>'+sub[18]+'</td><td><div class="csig" onmouseover=$(this).children("span.unshow").show() onmouseout=$(this).children("span.unshow").hide()>'\
                               +sub[9]+'</div></td><td><div class="bsig">'+str(sub[10])+'</div></td></tr>')
                
            summary.append("</tbody>")
    summary.append("</table><script language='JavaScript'>$('#filterName').keyup()</script>")
    #print time.time()
    #print summary
    #pdb.set_trace()
    return ''.join(summary)

if __name__=='__main__':
    #pdb.set_trace()
    usetime=100
    pcapNum=100
    #log=open('log.txt','w')
    files=[r'D:\all.pcap',]
    #node,totalflow,valid,invalid,error,L5node=finalNode(files,{},{})
    profile.run("finalNode(files,{},{})")
    #showNode(node,totalflow,valid,invalid,usetime,pcapNum,error,'fp','r')
    #log.close()
    
