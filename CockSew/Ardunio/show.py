import logging, sys, time, serial
from context import Screen, ScreenContext

import threading
from time import sleep
import serial



class Header:
    def render_header(self, ctx, tab, tab_name):
        # Print top row (tab name)
        ctx.home().bg_color(Screen.RED).fg_color(Screen.WHITE).write(tab_name)       
        columns = ctx.get_columns() - len(tab_name)
        empty_line = ""
        for i in range(0, columns):
            empty_line += " "
            
        ctx.write(empty_line)              
        time_str = time.strftime("%H:%M")
        
        columns = ctx.get_columns() - len(time_str)
        empty_line = ""
        for i in range(0, columns):
            empty_line += " "
            
        # Draw the time
        ctx.write(empty_line + time_str)              
        ctx.bg_color(Screen.BLACK)

class Thread_Manager(threading.Thread):
    def __init__(self, serial,):
        threading.Thread.__init__(self)
        self.val = ""
        self.ser = serial
    #def run(self):
    #    #self.read()
    #    print "nothing"  
    def returnPress(self):
        return self.ser.readline()
        pass    
    #def read(self):
    #    while True:
    #         print ser.readline()
    #         self.val = ser.readline()


ser = serial.Serial('/dev/ttyUSB0', 500000, timeout=0)
ReadThread = Thread_Manager(ser)
ReadThread.start()
ctx = ScreenContext("/dev/ttyUSB0")
ctx.sleep(6).reset_lcd().set_rotation(1)
counter = 0


print "rows", ctx.get_rows(), 320/ctx.get_rows()
print "columns", ctx.get_columns()
row = 21 * 2 * 8

while True:
    header = Header()
    header.render_header(ctx,0,"HeaderName")
    ctx.fg_color(Screen.RED).write("Hello").linebreak()
    ctx.fg_color(Screen.RED).write(str(counter)).linebreak()
    ctx.fg_color(Screen.BLUE).write("world!")
    ctx.fg_color(Screen.BLUE).write(ReadThread.returnPress())
    ctx.set_cursor_pos(row * 3,0)
    counter = counter + 1



