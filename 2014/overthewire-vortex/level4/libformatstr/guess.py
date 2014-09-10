#!/usr/bin/env python2
#-*- coding:utf-8 -*-

from .pattern import *
import sys

def guess_argnum(result, buffer_size, start_index=1):
    pattern_size = buffer_size // 8 
    pat = msfpattern(pattern_size * 4)
    if result[:len(pat)] != pat:
        return None
    result = result[len(pat):].replace("(nil)", "0x00000000").rstrip("X")

    parts = result.split("0x")[1:]
    for i, p in enumerate(parts):
        p = p.rjust(8, "0").decode("hex")[::-1]
        if p in pat:
            block_index = pat.find(p)
            padding = block_index % 4

            argnum = start_index + i * (pattern_size - 1)
            argnum -= block_index // 4
            return argnum, padding
    return None

if __name__ == "__main__":
    if len(sys.argv) > 1:
        lst = [sys.argv[1]] + map(int, sys.argv[2:])
        t = guess_argnum(*lst)
        if t:
            print "argnum:", t[0]
            print "padding:", t[1]
        else:
            print "Can't determing argnum!"
    else:
        print "Usage: guess result_str buffer_size [start_index=1]"