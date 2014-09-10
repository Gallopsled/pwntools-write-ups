#!/usr/bin/env python2
#-*- coding:utf-8 -*-

import re
import sys
import struct

def fmtemul(fmt, argnum, padding=0, start_len=0, debug=0):
    log = []
    writes = []

    count = start_len
    cursor = fmt
    while cursor:
        m = re.match(r"^%(\d+)[cdx]", cursor)
        if m:
            count += int(m.group(1))
            cursor = cursor[len(m.group(0)):]
            
            log.append( ("output+", int(m.group(1)), count) )
            if debug: print "output+", hex(int(m.group(1))), "=", hex(count)
            continue
        
        m = re.match(r"^%(\d+)\$hn", cursor)
        if m:
            num = int(m.group(1))
            index = padding + (num - argnum) * 4
            try:
                addr = struct.unpack("<I", fmt[index:index+4])[0]
            except:
                addr = 0xffffffff
            cursor = cursor[len(m.group(0)):]

            log.append( ("word", addr, count) )
            writes.append( (addr, 2, count) )
            if debug: print "set word", hex(addr), hex(count)
            continue

        m = re.match(r"^%(\d+)\$n", cursor)
        if m:
            num = int(m.group(1))
            index = padding + (num - argnum) * 4
            try:
                addr = struct.unpack("<I", fmt[index:index+4])[0]
            except:
                addr = 0xffffffff
            cursor = cursor[len(m.group(0)):]

            log.append( ("dword", addr, count) )
            writes.append( (addr, 4, count) )
            if debug: print "set dword", hex(addr), hex(count)
            continue

        cursor = cursor[1:]
        count += 1

        log.append( ("output+", 1, count) )
        if debug: print log[-1]
    return log, writes

def fmtprint(fmt, argnum, padding=0, start_len=0):
    return fmtemul(fmt, argnum, padding, start_len, debug=1)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        lst = [sys.argv[1]] + map(int, sys.argv[2:])
        fmtprint(*lst)
    else:
        print "Usage: fmtemul formatstr argnum [padding=0 [start_len=0]]"