#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
# Modifications 2011-2017 (C) Airbus, Louis.Granboulan@airbus.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
class bin_stream_mother(type):
    def __call__(self, *arg, **kargs):
        if arg and hasattr(arg[0], 'upper'):
            cls = bin_stream_str
        elif arg and hasattr(arg[0], 'fileno'):
            cls = bin_stream_file
        else:
            cls = bin_stream_virt

        i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        i.__init__(*arg, **kargs)
        return i

bin_stream_base = bin_stream_mother('bin_stream_base', (object,), {})
class bin_stream(bin_stream_base):
    def __init__(self, *args, **kargs):
        pass
    def __repr__(self):
        return "<%s !!>"%self.__class__.__name__

    def hexdump(self, offset, l):
        return

    def __getitem__(self, item):
        if not type(item) is slice: # integer
            self.offset = item
            return self.readbs(1)
        start = item.start
        stop  = item.stop
        step  = item.step
        self.offset = start
        s = self.readbs(stop-start)
        return s[::step]

class bin_stream_str(bin_stream):
    def __init__(self, bin, offset = 0):
        if offset>len(bin):
            raise IOError
        self.bin = bin
        self.offset = offset
        self.l = len(bin)
        if "is_addr_in" in self.bin.__class__.__dict__:
            self.is_addr_in = lambda ad:self.bin.is_addr_in(ad)

    def readbs(self, l=1):
        if self.offset+l>self.l:
            raise IOError
        self.offset+=l
        return self.bin[self.offset-l:self.offset]

    def writebs(self, l=1):
        raise ValueError('writebs unsupported')

    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        out =  self.bin[self.offset:]
        return out
    def setoffset(self, val):
        val = val & 0xFFFFFFFF
        self.offset = val

class bin_stream_file(bin_stream):
    def __init__(self, bin, offset):
        self.bin = bin
        self.bin.seek(0, 2)
        self.l = self.bin.tell()
        self.offset = offset

    def getoffset(self):
        return self.bin.tell()

    def setoffset(self, val):
        val = val & 0xFFFFFFFF
        self.bin.seek(val)
    offset = property(getoffset, setoffset)

    def readbs(self, l=1):
        if self.offset+l>self.l:
            raise IOError
        return self.bin.read(l)

    def writebs(self, l=1):
        if self.offset+l>self.l:
            raise IOError
        return self.bin.write(l)

    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        return str(self.bin)



class bin_stream_virt(bin_stream):
    def __init__(self, virt, offset = 0, section = None):
        if offset>virt.__len__():
            raise IOError
        self.virt = virt
        self.offset = offset
        self.section = section
        self.l = virt.__len__()
        if "is_addr_in" in self.virt.__class__.__dict__:
            self.is_addr_in = lambda ad:self.virt.is_addr_in(ad)

    def readbs(self, l=1):
        if self.offset+l>self.l:
            raise IOError
        self.offset+=l
        return self.virt(self.offset-l,self.offset,section=self.section)

    def writebs(self, l=1):
        raise ValueError('writebs unsupported')

    def __str__(self):
        raise AttributeError("Use pack() instead of str()")
    def pack(self):
        out =  self.virt[self.offset:]
        return out
    def setoffset(self, val):
        val = val & 0xFFFFFFFF
        self.offset = val
