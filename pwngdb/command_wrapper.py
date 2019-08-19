# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import gdb
from . import angelheap
from .utils import normalize_argv


class AngelHeapCmd(object):
    commands = []

    def __init__(self):
        # list all commands
        self.commands = [cmd for cmd in dir(self) if callable(getattr(self, cmd)) and not cmd.startswith("_")]

    def tracemalloc(self, *arg):
        """ Trace the malloc and free and detect some error """
        (option, ) = normalize_argv(arg, 1)
        if option == "on":
            try:
                angelheap.trace_malloc()
            except:
                print("Can't create Breakpoint")
        elif option == "off":
            angelheap.dis_trace_malloc()

    def heapinfo(self, *arg):
        """ Print some information of heap """
        (arena, ) = normalize_argv(arg, 1)
        angelheap.putheapinfo(arena)

    def heapinfoall(self):
        """ Print some information of multiheap """
        angelheap.putheapinfoall()

    def arenainfo(self):
        """ Print all arena info """
        angelheap.putarenainfo()

    def chunkinfo(self, *arg):
        """ Print chunk information of victim"""
        (victim, ) = normalize_argv(arg, 1)
        angelheap.chunkinfo(victim)

    def free(self, *arg):
        """ Print chunk is freeable """
        (victim, ) = normalize_argv(arg, 1)
        angelheap.freeptr(victim)

    def chunkptr(self, *arg):
        """ Print chunk information of user ptr"""
        (ptr, ) = normalize_argv(arg, 1)
        angelheap.chunkptr(ptr)

    def mergeinfo(self, *arg):
        """ Print merge information of victim"""
        (victim, ) = normalize_argv(arg, 1)
        angelheap.mergeinfo(victim)

    def force(self, *arg):
        """ Calculate the nb in the house of force """
        (target, ) = normalize_argv(arg, 1)
        angelheap.force(target)

    def fastbins(self):
        """ Print the fastbin """
        angelheap.putfastbin()

    def unsorted(self):
        """ Print the unsorted bin """
        angelheap.put_unsorted()

    def inused(self):
        """ Print the inuse chunk """
        angelheap.putinused()

    def parseheap(self):
        """ Parse heap """
        angelheap.parse_heap()

    def fakefast(self, *arg):
        (addr, size) = normalize_argv(arg, 2)
        angelheap.get_fake_fast(addr, size)

    def checkheap(self, *arg):
        """ Given an address and return the information of its heap """
        if len(arg) > 1:
            angelheap.check_heap(arg[0], arg[1])
        else:
            angelheap.check_heap(arg[0])


class CmdWrapper(gdb.Command):
    """ command wrapper """

    def __init__(self, cmd_name, cmd_obj):
        super(CmdWrapper, self).__init__(cmd_name, gdb.COMMAND_USER)
        self.cmd_obj = cmd_obj

    def try_eval(self, expr):
        try:
            return gdb.parse_and_eval(expr)
        except:
            # print("Unable to parse expression: {}".format(expr))
            return expr

    def eval_argv(self, expressions):
        """ Leave command alone, let GDB parse and evaluate arguments """
        return [expressions[0]] + [self.try_eval(expr) for expr in expressions[1:]]

    def invoke(self, args, from_tty):
        self.dont_repeat()
        expressions = gdb.string_to_argv(args)
        arg = self.eval_argv(expressions)
        if len(arg) > 0:
            cmd = arg[0]

            if cmd in self.cmd_obj.commands:
                func = getattr(self.cmd_obj, cmd)
                func(*arg[1:])
            else:
                print("Unknown command")
        else:
            print("Unknow command")

        return


class Alias(gdb.Command):
    def __init__(self, alias, command):
        self.command = command
        super(Alias, self).__init__(alias, gdb.COMMAND_NONE)

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("%s %s" % (self.command, args))
