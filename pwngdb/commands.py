from __future__ import print_function
import gdb
import subprocess
import re
from os import path, system
from .utils import normalize_argv, get_proc_map

# arch info
capsize = 0
word = ""
arch = ""
magic_variable = [
    "__malloc_hook", "__free_hook", "__realloc_hook", "stdin", "stdout", "_IO_list_all", "__after_morecore_hook"
]
magic_function = ["system", "execve", "open", "read", "write", "gets", "mprotect", "setcontext+0x35"]


class PwnCmd(object):
    commands = []
    prevbp = []
    bpoff = []

    def __init__(self):
        # list all commands
        self.commands = set([cmd for cmd in dir(self) if callable(getattr(self, cmd)) and not cmd.startswith("_")])
        self.no_eval_cmds = set(['off', 'bcall', 'findcall', 'rop'])
        self.normal_cmds = self.commands - self.no_eval_cmds

    def libc(self):
        """ Get libc base """
        libc_base = get_libc_base()
        if libc_base:
            print("\033[34m" + "libc: " + "\033[37m" + hex(libc_base))
        else:
            print('libc not found')

    def getheap(self):
        """ Get heap base """
        heap_base = get_heap_base()
        if heap_base:
            print("\033[35m" + "heap: " + "\033[37m" + hex(heap_base))
        else:
            print("heap not found")

    def ld(self):
        """ Get ld.so base """
        ld_base = get_ld_base()
        if ld_base:
            print("\033[34m" + "ld: " + "\033[37m" + hex(ld_base))
        else:
            print('ld not found')

    def codebase(self):
        """ Get code base """
        code_base, _ = get_code_base()
        if code_base:
            print("\033[34m" + "code: " + "\033[37m" + hex(code_base))
        else:
            print('code not found')

    def tls(self):
        """ Get tls base """
        tls_base = get_tls_base()
        if tls_base:
            print("\033[34m" + "tls: " + "\033[37m" + hex(tls_base))
        else:
            print('tls not found')

    def canary(self):
        """ Get canary value """
        print("\033[34m" + "canary: " + "\033[37m" + hex(get_canary()))

    def fmtarg(self, *arg):
        """ Calculate format argument offset """
        (addr, ) = normalize_argv(arg, 1)
        get_fmt_arg(addr)

    def off(self, *arg):
        """ Calculate offset to libc """
        (sym, ) = normalize_argv(arg, 1)
        sym_off = get_off(sym)
        if sym_off == 0xffffffffffffffff:
            print("Not found the symbol")
        else:
            if type(sym) is int:
                print("\033[34m" + hex(sym) + ": " + "\033[37m" + hex(sym_off))
            else:
                print("\033[34m" + sym + ": " + "\033[37m" + hex(sym_off))

    def fp(self, *arg):
        """ show FILE structure """
        (addr, ) = normalize_argv(arg, 1)
        show_fp(addr)

    def fpchain(self):
        """ show FILE chain """
        show_fp_chain()

    def orange(self, *arg):
        """ test house of orange """
        (addr, ) = normalize_argv(arg, 1)
        if addr:
            test_orange(addr)
        else:
            print("You need to specifiy an address")

    def fsop(self, *arg):
        """ test fsop """
        (addr, ) = normalize_argv(arg, 1)
        test_fsop(addr)

    def magic(self, *arg):
        """ Print usefual variables or function in glibc """
        (show_one, ) = normalize_argv(arg, 1)
        show_magic(show_one)

    def findsyscall(self):
        """ find the syscall gadget """
        start, end = get_code_base()
        if arch == "x86-64":
            gdb.execute("searchmem 0x050f " + hex(start) + " " + hex(end))
        elif arch == "i386":
            gdb.execute("searchmem 0x80cd " + hex(start) + " " + hex(end))
        elif arch == "arm":
            gdb.execute("searchmem 0xbc80df00 " + hex(start) + " " + hex(end))
        elif arch == "aarch64":
            gdb.execute("searchmem 0xd4000001 " + hex(start) + " " + hex(end))
        else:
            print("error")

    def got(self):
        """ Print the got table """
        proc_name = get_proc_name()
        if proc_name:
            cmd = "objdump -R "
            if is_cpp():
                cmd += "--demangle "
            cmd += '"{}"'.format(proc_name)
            got = subprocess.check_output(cmd, shell=True)[:-2].decode('utf8')
            print(got)
        else:
            print("No current process or executable file specified.")

    def dyn(self):
        """ Print dynamic section """
        proc_name = get_proc_name()
        if proc_name:
            dyn = subprocess.check_output('readelf -d "{}"'.format(proc_name), shell=True).decode('utf8')
            print(dyn)
        else:
            print("No current process or executable file specified.")

    def rop(self, *arg):
        """ ROPgadget """
        proc_name = get_proc_name()
        cmd = 'ROPgadget --binary "{}"'.format(proc_name)
        if proc_name:
            for s in arg:
                cmd += ' | grep "{}"'.format(s)
            subprocess.call(cmd, shell=True)
        else:
            print("No current process or executable file specified.")

    def findcall(self, *arg):
        """ Find some function call """
        (sym, ) = normalize_argv(arg, 1)
        output = search_call(sym)
        print(output)

    def bcall(self, *arg):
        """ Set the breakpoint at some function call """
        (sym, ) = normalize_argv(arg, 1)
        call = search_call(sym)
        if not call:
            print("symbol not found")
        else:
            if is_pie():
                code_start, code_end = get_code_base()
                for callbase in call.split('\n')[:-1]:
                    addr = int(callbase.split(':')[0], 16) + code_start
                    cmd = "b*" + hex(addr)
                    gdb.execute(cmd)
            else:
                for callbase in call.split('\n')[:-1]:
                    addr = int(callbase.split(':')[0], 16)
                    cmd = "b*" + hex(addr)
                    gdb.execute(cmd)


def is_cpp():
    proc_name = get_proc_name()
    data = subprocess.check_output("readelf -s " + proc_name, shell=True).decode('utf8')
    if "CXX" in data:
        return True
    else:
        return False


def get_proc_name(relative=False):
    proc_name = None
    try:
        data = gdb.execute("info proc exe", to_string=True)
        proc_name = re.search("exe.*", data).group().split("=")[1][2:-1]
    except:
        data = gdb.execute("info files", to_string=True)
        if data:
            proc_name = re.search('Symbols from "(.*)"', data).group(1)
    if proc_name and relative:
        return proc_name.split("/")[-1]
    return proc_name


def get_libc_base():
    proc_map = get_proc_map()
    data = re.search(r".*libc.*\.so", proc_map)
    if data:
        libc_base = data.group().split("-")[0]
        gdb.execute("set $libc=%s" % hex(int(libc_base, 16)))
        return int(libc_base, 16)
    else:
        return 0


def get_ld_base():
    proc_map = get_proc_map()
    data = re.search(r".*ld.*\.so", proc_map)
    if data:
        ldaddr = data.group().split("-")[0]
        gdb.execute("set $ld=%s" % hex(int(ldaddr, 16)))
        return int(ldaddr, 16)
    else:
        return 0


def get_heap_base():
    proc_map = get_proc_map()
    data = re.search(r".*heap\]", proc_map)
    if data:
        heap_base = data.group().split("-")[0]
        gdb.execute("set $heap=%s" % hex(int(heap_base, 16)))
        return int(heap_base, 16)
    else:
        return 0


def get_code_base():  # ret (start,end)
    proc_map = get_proc_map()
    proc_name = get_proc_name()
    pat = ".*" + proc_name
    data = re.findall(pat, proc_map)
    if data:
        code_start = data[0].split("-")[0]
        code_end = data[0].split("-")[1].split()[0]
        gdb.execute("set $code=%s" % hex(int(code_start, 16)))
        return (int(code_start, 16), int(code_end, 16))
    else:
        return (0, 0)


def get_tls_base():
    if arch == "i386":
        vsysaddr = gdb.execute("info functions __kernel_vsyscall", to_string=True).split("\n")[-2].split()[0].strip()
        sysinfo = gdb.execute("searchmem " + vsysaddr, to_string=True)
        match = re.search(r"mapped : .*(0x[0-9a-z]{8})", sysinfo)
        if match:
            tls_base = int(match.groups()[0], 16) - 0x10
        else:
            return 0
        return tls_base
    elif arch == "x86-64":
        gdb.execute("call (int)arch_prctl(0x1003, $rsp-8)", to_string=True)
        data = gdb.execute("x/xg $rsp-8", to_string=True)
        return int(data.split(":")[1].strip(), 16)
    else:
        return 0


def get_canary():
    tls_base = get_tls_base()
    if not tls_base:
        return 'error'
    if arch == "i386":
        offset = 0x14
        result = gdb.execute("x/xw " + hex(tls_base + offset), to_string=True).split(":")[1].strip()
        return int(result, 16)
    elif arch == "x86-64":
        offset = 0x28
        result = gdb.execute("x/xg " + hex(tls_base + offset), to_string=True).split(":")[1].strip()
        return int(result, 16)
    else:
        return "error"


def get_off(sym):
    libc = get_libc_base()
    if type(sym) is int:
        return sym - libc
    else:
        try:
            data = gdb.execute("x/x " + sym, to_string=True)
            if "No symbol" in data:
                return 0xffffffffffffffff
            else:
                data = re.search("0x.*[0-9a-f] ", data).group()
                sym_addr = int(data[:-1], 16)
                return sym_addr - libc
        except:
            return 0xffffffffffffffff


def search_call(sym):
    proc_name = get_proc_name()
    cmd = "objdump -d -M intel "
    if is_cpp():
        cmd += "--demangle "
    cmd += '"{}"'.format(proc_name)
    try:
        call = subprocess.check_output(cmd + "| grep \"call.*" + sym + "@plt>\"", shell=True).decode('utf8')
        return call
    except:
        return ''


def is_pie():
    proc_name = get_proc_name()
    result = subprocess.check_output('readelf -h -wN "{}"'.format(proc_name), shell=True).decode('utf8')
    return 'Type:' in result and 'DYN (' in result


def get_reg(reg):
    cmd = "info register " + reg
    result = int(gdb.execute(cmd, to_string=True).split()[1].strip(), 16)
    return result


def show_fp(addr):
    if addr:
        cmd = "p *(struct _IO_FILE_plus *)" + hex(addr)
        try:
            gdb.execute(cmd)
        except gdb.error:
            print("Can't not access 0x%x" % addr)
    else:
        print("You need to specify an address")


def show_fp_chain():
    cmd = "x/" + word + "&_IO_list_all"
    head = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
    print("\033[32mfpchain:\033[1;37m ", end="")
    chain = head
    print("0x%x" % chain, end="")
    try:
        while chain != 0:
            print(" --> ", end="")
            cmd = "x/" + word + "&((struct _IO_FILE_plus *)" + hex(chain) + ").file._chain"
            chain = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            print("0x%x" % chain, end="")
        print("")
    except:
        print("Chain is corrupted")


def test_orange(addr):
    result = True
    cmd = "x/" + word + "&((struct _IO_FILE_plus *)" + hex(addr) + ").file._mode"
    mode = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xffffffff
    cmd = "x/" + word + "&((struct _IO_FILE_plus *)" + hex(addr) + ").file._IO_write_ptr"
    write_ptr = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
    cmd = "x/" + word + "&((struct _IO_FILE_plus *)" + hex(addr) + ").file._IO_write_base"
    write_base = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
    if mode < 0x80000000 and mode != 0:
        try:
            cmd = "x/" + word + "&((struct _IO_FILE_plus *)" + hex(addr) + ").file._wide_data"
            wide_data = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            cmd = "x/" + word + "&((struct _IO_wide_data *)" + hex(wide_data) + ")._IO_write_ptr"
            w_write_ptr = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            cmd = "x/" + word + "&((struct _IO_wide_data *)" + hex(wide_data) + ")._IO_write_base"
            w_write_base = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            if w_write_ptr <= w_write_base:
                print("\033[;1;31m_wide_data->_IO_write_ptr(0x%x) < _wide_data->_IO_write_base(0x%x)\033[1;37m" %
                      (w_write_ptr, w_write_base))
                result = False
        except:
            print("\033;1;31mCan't access wide_data\033[1;37m")
            result = False
    else:
        if write_ptr <= write_base:
            print("\033[;1;31m_IO_write_ptr(0x%x) < _IO_write_base(0x%x)\033[1;37m" % (write_ptr, write_base))
            result = False
    if result:
        print("Result : \033[34mTrue\033[37m")
        cmd = "x/" + word + "&((struct _IO_FILE_plus *)" + hex(addr) + ").vtable.__overflow"
        overflow = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        print("Func : \033[33m 0x%x\033[1;37m" % overflow)
    else:
        print("Result : \033[31mFalse\033[1;37m")


def test_fsop(addr=None):
    if addr:
        cmd = "x/" + word + hex(addr)
    else:
        cmd = "x/" + word + "&_IO_list_all"
    head = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
    chain = head
    print("---------- fp : 0x%x ----------" % chain)
    test_orange(chain)
    try:
        while chain != 0:
            cmd = "x/" + word + "&((struct _IO_FILE_plus *)" + hex(chain) + ").file._chain"
            chain = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            if chain != 0:
                print("---------- fp : 0x%x ----------" % chain)
                test_orange(chain)
    except:
        print("Chain is corrupted")


def get_fmt_arg(addr):
    if not addr:
        print("You need to specify a stack address")
        return
    if arch == "i386":
        start = get_reg("esp")
        idx = (addr - start) / 4 + 1
        print('The index of format argument : %d ("%%%d$p")' % (idx, idx - 1))
    elif arch == "x86-64":
        start = get_reg("rsp")
        idx = (addr - start) / 8 + 7
        print('The index of format argument : %d ("%%%d$p")' % (idx, idx - 1))
    else:
        print("Not support the arch")


def show_magic(show_one):
    try:
        proc_map = get_proc_map()
        libc = get_libc_base()
        data = re.findall(r'\S+/libc.+\.so.*', proc_map)
        if data:
            libc_path = data[0].split()[-1]
        print("========== function ==========")
        for f in magic_function:
            cmd = "x/" + word + "&" + f
            func_addr = gdb.execute(cmd, to_string=True).split()[0].strip()
            to_print = "\033[34m%s\033[33m(%s)\033[37m" % (f, hex(get_off(f)))
            to_print = to_print.ljust(36 + 15, ' ') + func_addr
            print(to_print)
        print("\033[00m========== variables ==========")
        for v in magic_variable:
            cmd = "x/" + word + "&" + v
            output = gdb.execute(cmd, to_string=True)
            var_addr = output.split()[0].strip()
            var_content = output.split(':')[1].strip()
            offset = hex(get_off("&" + v))
            to_print = '\033[34m%s\033[33m(%s)\033[37m' % (v, offset)
            to_print = to_print.ljust(36 + 15, ' ')
            to_print += '%s: \033[37m%s' % (var_addr, var_content)
            print(to_print)
        if libc_path:
            cmd = 'strings -t x {} | grep "/bin/sh"'.format(libc_path)
            binsh_off = subprocess.check_output(cmd, shell=True).decode('utf8').split()[0]
            binsh_addr = libc + int(binsh_off, 16)
            cmd = "x/" + word + hex(binsh_addr)
            binsh_content = gdb.execute(cmd, to_string=True).split(':')[1].strip()
            to_print = '\033[34m"/bin/sh"\033[33m(0x%s)\033[37m' % binsh_off
            to_print = to_print.ljust(36 + 15, ' ')
            to_print += '0x%x: \033[37m%s' % (binsh_addr, binsh_content)
            print(to_print)
            # print one gadget
            if show_one and path.isfile('/usr/local/bin/one_gadget'):
                print("========== one gadget ==========")
                system("one_gadget {}".format(libc_path))
    except:
        print("Error occured, you may need run the program first")
