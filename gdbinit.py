# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
from os import path

directory, _file = path.split(__file__)
directory = path.expanduser(directory)
directory = path.abspath(directory)

sys.path.append(directory)

import pwngdb
from pwngdb import angelheap, gdbpwnpwnpwn