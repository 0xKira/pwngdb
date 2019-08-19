# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import gdb
from . import angelheap
from . import gdbpwnpwnpwn
from .commands import PwnCmd
from .command_wrapper import AngelHeapCmd, CmdWrapper, Alias

angelheap_cmd = AngelHeapCmd()
CmdWrapper('angelheap', angelheap_cmd)
for cmd in angelheap_cmd.commands:
    Alias(cmd, 'angelheap {}'.format(cmd))

pwn_cmd = PwnCmd()
CmdWrapper('pwngdb', pwn_cmd)
for cmd in pwn_cmd.commands:
    Alias(cmd, 'pwngdb {}'.format(cmd))

gdb.execute('set print asm-demangle on')

# for debug usage
# import traceback
# def _execute(cmd, to_string=False):
#     try:
#         out = gdb._never_guess(cmd, to_string=to_string)
#         if to_string:
#             return out
#         else:
#             return True
#     except Exception as e:
#         print('=' * 40)
#         print(cmd, to_string)
#         traceback.print_exc()
#         print('=' * 40)
#         return False

# gdb._never_guess = gdb.execute
# gdb.execute = _execute