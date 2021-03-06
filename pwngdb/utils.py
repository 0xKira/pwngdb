# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import gdb
import re
import os


def get_libc_version():
    try:
        return float(gdb.execute("x/s __libc_version", to_string=True).split()[2].strip("\""))
    except:
        print("Can not get libc version")
        return 0


def reveal_ptr(addr_of_entry, entry):
    return (addr_of_entry >> 12) ^ entry


def get_arch():
    data = gdb.execute('show arch', to_string=True)
    tmp = re.search("currently.*", data)
    if tmp:
        info = tmp.group()
        if "x86-64" in info:
            return "x86-64", "gx ", 8
        elif "aarch64" in info:
            return "aarch64", "gx ", 8
        elif "arm" in info:
            return "arm", "wx ", 4
        else:
            return "i386", "wx ", 4
    else:
        return None, None, None


def get_gdb_map():
    """
    Use gdb command 'info proc mappings' to get the memory mapping
    Notice: No permission info
    """
    resp = gdb.execute("info proc mappings", to_string=True).split("\n")
    resp = '\n'.join(resp[i] for i in range(4, len(resp))).strip().split("\n")
    gdb_map = ""
    for l in resp:
        line = ""
        first = True
        for sep in l.split(" "):
            if len(sep) != 0:
                if first:  # start address
                    line += sep + "-"
                    first = False
                else:
                    line += sep + " "
        line = line.strip() + "\n"
        gdb_map += line
    return gdb_map


def get_proc_map():
    data = gdb.execute('info proc exe', to_string=True)
    pid = re.search('process.*', data)
    if pid:
        pid = pid.group()
        pid = pid.split()[1]
        fpath = "/proc/" + pid + "/maps"
        if os.path.isfile(fpath):  # if file exist, read memory mapping directly from file
            maps = open(fpath)
            proc_map = maps.read()
            maps.close()
            return proc_map
        else:  # if file doesn't exist, use 'info proc mappings' to get the memory mapping
            return get_gdb_map()
    else:
        return "error"


def to_int(val):
    """
    Convert a string to int number
    from https://github.com/longld/peda
    """
    try:
        return int(str(val), 0)
    except:
        return None


def normalize_argv(args, size=0):
    """
    Normalize argv to list with predefined length
    from https://github.com/longld/peda
    """
    args = list(args)
    for (idx, val) in enumerate(args):
        if to_int(val) is not None:
            args[idx] = to_int(val)
        if size and idx == size:
            return args[:idx]

    if size == 0:
        return args
    for i in range(len(args), size):
        args += [None]
    return args
