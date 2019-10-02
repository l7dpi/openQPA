#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
@author zhuzhu
@contact QQ327909056
'''

import sys,os
from os import getcwd
from PyQt4.QtGui import QSystemTrayIcon,QApplication,QAction,QIcon,QMenu
from PyQt4.QtCore import QTextCodec,Qt
import AppProperty
from Window import Window
from PyQt4.QtNetwork import QNetworkCookieJar

reload(sys)
sys.setdefaultencoding('utf-8')


def main():
    # 每一个PyQt4程序都必须创建一个QApplication对象[QtGui.QApplication(sys.argv)]
    app = QApplication(sys.argv)
    QTextCodec.setCodecForCStrings(QTextCodec.codecForName("GBK"))
    initProperty()
    AppProperty.MainWin = Window("main.html",1300,600)
    AppProperty.MainWin.show()
    createTray()
    sys.exit(app.exec_())
    
def createTray():
    #托盘
    AppProperty.TrayIcon=QSystemTrayIcon(AppProperty.AppIcon,AppProperty.MainWin)
    AppProperty.TrayIcon.activated.connect(trayClick)
    AppProperty.TrayIcon.setToolTip("QPA")
    AppProperty.TrayIcon.setContextMenu(createTrayMenu(AppProperty.TrayIcon))
    AppProperty.TrayIcon.show()

def trayClick(reason):
    if(reason==3):
        if AppProperty.MainWin.isHidden():
            AppProperty.MainWin.show()
        AppProperty.MainWin.activateWindow()
    
def createTrayMenu(trayIcon):
    trayIconMenu = QMenu()
    action = QAction(u"退出",trayIcon)
    action.triggered.connect(QPAquit)
    trayIconMenu.addAction(action)
    return trayIconMenu
    
    
def initProperty():
    AppProperty.AppTitle = "QPA"
    AppProperty.AppIcon = QIcon("imgs/icon.png")
    AppProperty.HomeDir = getcwd()
    AppProperty.CookieJar = QNetworkCookieJar()

def QPAquit():
    QApplication.instance().quit()
    os.popen("taskkill /F /IM CAP.exe")
    return 'ok'
    
if __name__ == "__main__":
    main()  
