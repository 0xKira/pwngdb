# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from os import path

directory, _file = path.split(__file__)
directory = path.expanduser(directory)
directory = path.abspath(directory)
directory = path.join(directory, 'pwngdb')

sys.path.append(directory)

import command_wrapper
import angelheap

command_wrapper.angelheap_cmd = command_wrapper.AngelHeapCmd()
command_wrapper.AngelHeapCmdWrapper()
for cmd in command_wrapper.angelheap_cmd.commands:
    command_wrapper.Alias(cmd, "angelheap %s" % cmd)

import gdbpwnpwnpwn
import commands
