# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from os import path

directory, _file = path.split(__file__)
directory = path.expanduser(directory)
directory = path.abspath(directory)
directory = path.join(directory, 'pwngdb')

sys.path.append(directory)

import gdbpwnpwnpwn
from command_wrapper import AngelHeapCmd, CmdWrapper, Alias
import angelheap
from commands import PwnCmd

angelheap_cmd = AngelHeapCmd()
CmdWrapper('angelheap', angelheap_cmd)
for cmd in angelheap_cmd.commands:
    Alias(cmd, 'angelheap {}'.format(cmd))

pwn_cmd = PwnCmd()
CmdWrapper('pwngdb', pwn_cmd)
for cmd in pwn_cmd.commands:
    Alias(cmd, 'pwngdb {}'.format(cmd))

gdb.execute('set print asm-demangle on')
