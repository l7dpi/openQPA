#! /usr/bin/env python  
# -*- coding: utf-8 -*-
'''
@author zhuzhu
@contact QQ327909056
'''
import os,re
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from RoundWindow import RoundWindow
from PyQt4.QtWebKit import *
import httplib2
import AppProperty
import base64
import webbrowser
import analysis2,calc,dpcap
import time
from subprocess import *
import datetime
import calc
import connect

class Window(RoundWindow): 
    def __init__(self, url,width,height,windowType=0,handleMethod=""):  
        super(Window, self).__init__()
        self.sflag=1
        self.resize(width,height)
        self.round()
        self.setWindowTitle(AppProperty.AppTitle)
        self.setWindowIcon(AppProperty.AppIcon)
        self.webview = QWebView(self)

        self.webview.settings().setAttribute(QWebSettings.DeveloperExtrasEnabled, True)
        self.webview.settings().setAttribute(QWebSettings.LocalContentCanAccessRemoteUrls, True)
        self.webview.settings().setAttribute(QWebSettings.LocalStorageEnabled, True)
        self.webview.settings().setLocalStoragePath(AppProperty.HomeDir+"/data")
        self.webview.setContextMenuPolicy(Qt.NoContextMenu)
        self.webview.settings().setDefaultTextEncoding("utf-8")
        self.webview.setGeometry(1,1,self.width()-2,self.height()-2)
        self.webview.setStyleSheet("QWebView{background-color: rgba(255, 193, 245, 0%); }")
        self.webview.page().networkAccessManager().setCookieJar(AppProperty.CookieJar)
        self.webview.page().mainFrame().javaScriptWindowObjectCleared.connect(self.setJavaScriptObject)
        self.webview.page().linkClicked.connect(self.linkClicked)
        self.webview.page().setLinkDelegationPolicy(QWebPage.DelegateAllLinks)

        self.handleMethod= handleMethod
        self.subUrl=url
        self.windowType=windowType
        self.url = QUrl.fromLocalFile(AppProperty.HomeDir+"/html/window.html")
        self.webview.load(self.url)
        self.sources=[]
        self.defaultDir="./"
        self.setting=eval(open('./conf/PA.cfg','r').read())
        self.opensig = []
        self.wtool=self.setting['wireshark']
        self.nFilter=self.setting['filter']['port']
        self.sclass='r'
        self.iclass='r'
        self.node=None
        self.nicID=1
        self.nicType=0
        self.pre_L5node={}
        self.screen=QDesktopWidget().screenGeometry()
        self.pname_size={}
         
    def linkClicked(self,url):
        webbrowser.open(url.toString())
     
    def setJavaScriptObject(self):
        self.webview.page().mainFrame().addToJavaScriptWindowObject("_window_", self)

    @pyqtSignature("",result="QString")
    def addFiles(self):
        files = QFileDialog.getOpenFileNames(self, u"选择pcap包--仅支持libpcap格式",self.defaultDir,"pcap file(*.pcap *.cap)")

        if not files:
            return 'NULL'
        #初始化，重新选择数据
        self.sources=[]
        self.pre_L5node={}
        back=''
        for string in files:
            self.sources.append(string)
            if back=='':
                seq=''
            else:
                seq='|'
            size=calc.cflow( os.path.getsize(string) )          
            back+=seq+string+'<td>'+size+'</td>'

        self.defaultDir= u'/'.join(re.split('[/\\\]',str(self.sources[0]))[0:-1])
        #win7 XP different:/ or \
        #print self.sources
        #print self.defaultDir
        return back

    @pyqtSignature("",result="QString")
    def addCap(self):
        files = QFileDialog.getOpenFileNames(self, u"选择pcap包--仅支持libpcap格式",self.defaultDir,"pcap file(*.pcap *.cap)")

        if not files:
            return 'NULL'
        for string in files:
            if string not in self.sources:
                self.sources.append(string)
        self.defaultDir= u'/'.join(re.split('[/\\\]',str(self.sources[-1]))[0:-2])
        back=''
        for string in self.sources:
            if back=='':
                seq=''
            else:
                seq='|'
            size=calc.cflow( os.path.getsize(string) )          
            back+=seq+string+'<td>'+size+'</td>'
        return back

    @pyqtSignature("QString",result="QString")
    def delCap(self,mstr):
        try:
            self.sources.remove(mstr)
        except:
            pass
        back=''
        for string in self.sources:
            if back=='':
                seq=''
            else:
                seq='|'
            size=calc.cflow( os.path.getsize(string) )          
            back+=seq+string+'<td>'+size+'</td>'
        return back  
        
    @pyqtSignature("QString",result="QString")
    def wa(self,mstr):
        self.pre_L5node={}
        self.nicID=str(mstr).split('-')[0]
        self.nicType=str(mstr).split('-')[1]
        self.capDir=datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        connect.exeCap(self.nicID,self.capDir,self.nicType)
        self.pname_size={}
        self.ptime = time.time()
        return "OK"
    
    @pyqtSignature("",result="QString")
    def showNIC(self):
        sn=connect.exeNic()
        nlist=sn.stdout.readlines()
        back=""
        for i in range(len(nlist)):
            back+="<option value="+str(i+1)+" title='"+nlist[i]+"'>"+nlist[i]+"</option>"
        #print nlist
        if nlist==[]:
            back=""
        #print back
        return back

    @pyqtSignature("",result="QString")
    def readCap(self):
        self.absdir=os.getcwd()+'\\'+self.capDir
        setting=[]
        psize=[]
        for r,ds,fs in os.walk(self.absdir):
            for pname in fs:
                size=os.path.getsize(os.path.join(r,pname))
                if pname in self.pname_size:
                    addsize=size-self.pname_size[pname]
                else:
                    addsize=size
                psize.append([pname,size,addsize])
                self.pname_size[pname]=size
        #psize.sort(key=lambda ps:ps[2],reverse=True)
        if(len(psize)>0):
            setting.append(u"<table id='Cap'><tr style='background-color:rgb(220,220,220);'><th></th><th></th><th style='text-align:left'>进程名</th>\
                           <th style='text-align:right;width:200px;'>字节数Bytes</th><th style='text-align:right;width:200px;'>当前速度KBytes/s</th>\
                           <th style='text-align:right;width:200px;'>平均速度KBytes/s</th></tr>")
            for pname,size,addsize in psize:
                pname=pname.decode('gbk').encode('utf-8')
                if self.absdir.decode('gbk').encode('utf-8')+"\\"+pname in self.sources:
                    check="checked"
                    color="red"
                else:
                    check=""
                    color=""
                setting.append("<tr><td><div class='wireshark' id='PCAP_"+self.absdir.decode('gbk').encode('utf-8')+"\\"+pname+"' onclick=openPcap(this.id)></div></td><td class='Capchoose'>"
                               +"<input "+check+" onclick='updateSource()' type='checkbox' id='"+self.absdir.decode('gbk').encode('utf-8')+"\\"+pname+"'></td>"
                               +"<td style='color:"+color+"' >"+pname+"</td>"
                               +"<td style='text-align:right'>&nbsp;&nbsp;"+str(size)+"</td>"
                               +"<td style='text-align:right'>&nbsp;&nbsp;"+str("%.3f" %(float(addsize)/1024/1))+"</td>"
                               +"<td style='text-align:right'>&nbsp;&nbsp;"+str("%.3f" %(float(size)/1024/(time.time()-self.ptime)))+"</td></tr>")
            setting.append("</table>")
        setting.append(u"<h3 style='background-color:rgb(220,220,220);'>包文件存储目录："+self.absdir.decode('gbk').encode('utf-8')+"</h3>")
        return ''.join(setting)
    
    @pyqtSignature("",result="QString")
    def stopCap(self):
        os.popen("taskkill /F /IM CAP.exe")
        return "OK"
        
    @pyqtSignature("",result="QString")
    def startAna(self):
        self.M=0
        self.L=0
        starttime=time.time()
        self.node,self.totalflow,self.valid,self.invalid,self.error,self.pre_L5node=analysis2.finalNode(self.sources,self.nFilter,self.pre_L5node,self.opensig)
        overtime=time.time()
        self.usetime=overtime-starttime
        self.pcapNum=len(self.sources)
        return analysis2.showNode(self.node,self.totalflow,self.valid,self.invalid,self.usetime,self.pcapNum,self.error,self.sclass,self.iclass)
    
    @pyqtSignature("QString",result="QString")
    def updateSource(self,mstr):
        self.sources=unicode(str(mstr)).split(',')
        return "OK"
    
    @pyqtSignature("QString",result="QString")
    def delete(self,mstr):
        dlist=str(mstr).split(',')
        for key in dlist:
            del self.node[key]
        return analysis2.showNode(self.node,self.totalflow,self.valid,self.invalid,self.usetime,self.pcapNum,self.error,self.sclass,self.iclass)

    @pyqtSignature("QString",result="QString")
    def doSort(self,mstr):
        self.sclass=mstr
        if self.node:
            return analysis2.showNode(self.node,self.totalflow,self.valid,self.invalid,self.usetime,self.pcapNum,self.error,self.sclass,self.iclass)
        else:
            return ''

    @pyqtSignature("QString",result="QString")
    def doSessionSort(self,mstr):
        self.iclass=mstr
        if self.node:
            return analysis2.showNode(self.node,self.totalflow,self.valid,self.invalid,self.usetime,self.pcapNum,self.error,self.sclass,self.iclass)
        else:
            return ''

    @pyqtSignature("QString",result="QString")
    def openPcap(self,mstr):
        dlist=str(mstr).split('_')
        #print dlist
        if dlist[0]=='PCAP':
            cmd=' '.join([self.wtool,'-r','"'+unicode(str(mstr)[5:]).encode('GBK').replace('\\','/')+'"'])
        else:
            if dlist[5]=='TCP':
                pfilter=''.join(['ip.addr==',dlist[1],'&&tcp.port==',dlist[2],'&&ip.addr==',dlist[3],'&&tcp.port==',dlist[4]])
            else:
                pfilter=''.join(['ip.addr==',dlist[1],'&&udp.port==',dlist[2],'&&ip.addr==',dlist[3],'&&udp.port==',dlist[4]])
            cmd=' '.join([self.wtool,'-R','"'+(pfilter)+'"','-r','"'+unicode(self.sources[int(dlist[0])]).encode('GBK').replace('\\','/')+'"'])
        try:
            Popen(cmd)
        except WindowsError:
            files = QFileDialog.getOpenFileName(self, u"没有找到Wireshark.exe程序，请指定，",'./',"wireshark.exe(*.exe)")
            self.wtool=unicode(files).encode('GBK')
            conf=open('./conf/PA.cfg','w')
            self.setting['wireshark']=self.wtool
            conf.writelines(repr(self.setting))
            conf.close
        return 'OK'
    
    @pyqtSignature("")
    def minimize(self):
        if(self.windowType==0):
            self.hide()
        else:
            self.showMinimized()


    def normalmize(self):
        self.webview.resize(1300,600)
        self.resize(1300,600)
        size=self.geometry()
        self.move((self.screen.width()-size.width())/2,(self.screen.height()-size.height())/2)
        self.round()
            

    def maximize(self):
        desktop = QApplication.desktop()
        rect = desktop.availableGeometry()
        self.setGeometry(rect)
        self.webview.setGeometry(rect)
        self.round()
        
    @pyqtSignature("")
    def changemize(self):
        if self.sflag==1:
            self.maximize()
            self.sflag=0
        else:
            self.normalmize()
            self.sflag=1
            
    @pyqtSignature("")
    def quit(self):
        if(self.windowType==0):
            res = QMessageBox.question(self, u"关闭提示", u"你点击了关闭按钮\n你是想“最小化”还是“退出”？",u"最小化", u"退出",u"取消",0,2)
            if(res==1):
                QApplication.instance().quit()
                os.popen("taskkill /F /IM CAP.exe")
            elif(res==0):
                self.hide()
        else:
            self.close()
    
    @pyqtSignature("int,int")
    def moveTo(self,offsetX,offsetY):
        self.nowX=self.nowX+offsetX
        self.nowY=self.nowY+offsetY
        if(self.nowY<0):
            self.nowY=0
        elif(self.nowY>self.safeHeight):
            self.nowY=self.safeHeight
        self.move(self.nowX,self.nowY)

    @pyqtSignature("")
    def Here(self):
        self.nowX=self.x()
        self.nowY=self.y()
        self.safeHeight=self.screen.height()-50
        #print self.nowX,self.nowY
        
    @pyqtSignature("QString,int,int,int,QString")
    def open(self,url,width,height,windowType,handleMethod):
        win = Window(url,width,height,windowType,handleMethod)
        win.show()
        qe = QEventLoop()
        qe.exec_()

    @pyqtSignature("",result="QString")
    def installWinPcap(self):
        connect.exeWinPcap()
        return ''
