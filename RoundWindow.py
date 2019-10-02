#! /usr/bin/env python  
# -*- coding: utf-8 -*-
'''
@contact QQ327909056
'''
from PyQt4.QtGui import QBitmap,QPainter,QColor,QWidget
from PyQt4.QtCore import QPointF,Qt

class RoundWindow(QWidget): 
    def __init__(self):
        super(RoundWindow, self).__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
            
    def round(self):
        bmp = QBitmap(self.size())
        p = QPainter()
        p.begin(bmp)
        p.fillRect(bmp.rect(), Qt.white)
        p.setBrush(QColor(0,0,0))
        p.drawRoundedRect(bmp.rect(), 5, 5)
        p.setPen(QColor(255,255,255,255))
        p.drawPoints(QPointF(self.width()-2,self.height()-1), QPointF(self.width()-1,self.height()-2))
        p.setPen(QColor(0,0,0))
        p.drawPoints(QPointF(0,2),QPointF(3,0),QPointF(2,0),QPointF(1,1))
        p.end()
        self.setMask(bmp)
        
    def paintEvent(self,event):
        p = QPainter(self)
        p.setBrush(QColor(0xf9f9f9))
        p.setPen(QColor(0x49585f))
        p.drawRoundedRect(0, 0, self.width()-1, self.height()-1, 3, 3)
