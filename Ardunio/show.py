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

#class Thread_Manager(threading.Thread):
#    def __init__(self, serial,):
#        threading.Thread.__init__(self)
#        self.val = ""
#        self.ser = serial
#    #def run(self):
#    #    #self.read()
#    #    print "nothing"  
#    def returnPress(self):
#        return self.ser.readline()
#        pass    
#    #def read(self):
#    #    while True:
#    #         print ser.readline()
#    #         self.val = ser.readline()

class Thread_Manager(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.val = ""
        self.ser = serial
        self.mess1 = "hello"
        self.mess2 = "World!"
        self.ser = serial.Serial("/dev/ttyUSB0", 500000, timeout=0)
        self.ctx = ScreenContext("/dev/ttyUSB0")
        self.ctx.sleep(6).reset_lcd().set_rotation(1)
        self.counter = 0
        #print "rows", ctx.get_rows(), 320/ctx.get_rows()
        #print "columns", ctx.get_columns()
        self.row = 21 * 2 * 8
        print "Start LCD"
  
  
    #def run(self):
    #    while True:
    #        header = Header()
    #        header.render_header(self.ctx,0,"HeaderName")
    #        self.ctx.fg_color(Screen.RED).write(self.mess1).linebreak()
    #        self.ctx.fg_color(Screen.RED).write(str(self.counter)).linebreak()
    #        self.ctx.fg_color(Screen.BLUE).write(self.mess2)
    #        #ctx.fg_color(Screen.BLUE).write(ReadThread.returnPress())
    #        self.ctx.set_cursor_pos(self.row * 3,0)
    #        self.counter += 1

    def update_screen(self):
        self.ctx.sleep(6).reset_lcd().set_rotation(1)
        header = Header()
        header.render_header(self.ctx,0,"Rouge")
        self.ctx.fg_color(Screen.RED).write(self.mess1).linebreak()
        self.ctx.fg_color(Screen.RED).write(str(self.counter)).linebreak()
        self.ctx.fg_color(Screen.BLUE).write(self.mess2)
        #ctx.fg_color(Screen.BLUE).write(ReadThread.returnPress())
        self.ctx.set_cursor_pos(self.row * 3,0)
        self.counter += 1  

    def update_message(self, mess1, mess2):
        self.mess1 = mess1
        self.mess2 = mess2
        return True
        
    


t = Thread_Manager()
t.start()



#header = Header()
#header.render_header(ctx,0,"Rouge Hunter")
#ctx.fg_color(Screen.RED).write("Hello").linebreak()
#ctx.fg_color(Screen.RED).write(str(counter)).linebreak()
#ctx.fg_color(Screen.BLUE).write("world!")
##ctx.fg_color(Screen.BLUE).write(ReadThread.returnPress())
#ctx.set_cursor_pos(row * 3,0)
#counter = counter + 1



