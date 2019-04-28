from __future__ import print_function
import gdb
import subprocess
import re
from os import path, system

directory, file = path.split(__file__)
directory = path.expanduser(directory)
directory = path.abspath(directory)
# sys.path.append(directory)

# arch
capsize = 0
word = ""
arch = ""
magic_variable = ["__malloc_hook", "__free_hook", "__realloc_hook", "stdin", "stdout", "_IO_list_all",
                  "__after_morecore_hook"]
magic_function = ["system", "execve", "open", "read", "write", "gets", "mprotect", "setcontext+0x35"]


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


class PwnCmd(object):
    commands = []
    prevbp = []
    bpoff = []

    def __init__(self):
        # list all commands
        self.commands = [cmd for cmd in dir(self) if callable(getattr(self, cmd))]

    def libc(self):
        """ Get libc base """
        libcbs = libcbase()
        if libcbs:
            print("\033[34m" + "libc : " + "\033[37m" + hex(libcbs))
        else:
            print('libc not found')

    def getheap(self):
        """ Get heapbase """
        heapbase = getheapbase()
        if heapbase:
            print("\033[35m" + "heap base : " + "\033[37m" + hex(heapbase))
        else:
            print("heap not found")

    def ld(self):
        """ Get ld.so base """
        ldbs = ldbase()
        if ldbs:
            print("\033[34m" + "ld : " + "\033[37m" + hex(ldbs))
        else:
            print('ld base not found')

    def codebase(self):
        """ Get text base """
        codebs = codeaddr()[0]
        if codebs:
            print("\033[34m" + "codebase : " + "\033[37m" + hex(codebs))
        else:
            print('code base not found')

    def tls(self):
        """ Get tls base """
        tls = gettls()
        if tls:
            print("\033[34m" + "tls : " + "\033[37m" + hex(tls))
        else:
            print('tls not found')

    def canary(self):
        """ Get canary value """
        print("\033[34m" + "canary : " + "\033[37m" + hex(getcanary()))

    def fmtarg(self, *arg):
        (addr,) = normalize_argv(arg, 1)
        getfmtarg(addr)

    def off(self, *arg):
        """ Calculate offset to libc """
        (sym,) = normalize_argv(arg, 1)
        symaddr = getoff(sym)
        if symaddr == 0:
            print("Not found the symbol")
        else:
            if type(sym) is int:
                print("\033[34m" + hex(sym) + ": " + "\033[37m" + hex(symaddr))
            else:
                print("\033[34m" + sym + ": " + "\033[37m" + hex(symaddr))

    def fp(self, *arg):
        """ show FILE structure """
        (addr,) = normalize_argv(arg, 1)
        showfp(addr)

    def fpchain(self):
        """ show FILE chain """
        showfpchain()

    def orange(self, *arg):
        """ test house of orange """
        (addr,) = normalize_argv(arg, 1)
        if addr:
            testorange(addr)
        else:
            print("You need to specifiy an address")

    def fsop(self, *arg):
        """ test fsop """
        (addr,) = normalize_argv(arg, 1)
        testfsop(addr)

    def magic(self):
        """ Print usefual variables or function in glibc """
        getarch()

        try:
            infomap = procmap()
            libc_base = libcbase()
            data = re.findall('\S*libc.*\.so.*', infomap)
            if data:
                libc_path = data[0].split()[-1]
            print("========== function ==========")
            for f in magic_function:
                cmd = "x/" + word + "&" + f
                func_addr = gdb.execute(cmd, to_string=True).split()[0].strip()
                to_print = "\033[34m%s\033[33m(%s)\033[37m" % (f, hex(getoff(f)))
                to_print = to_print.ljust(36 + 15, ' ') + func_addr
                print(to_print)
            print("========== variables ==========")
            for v in magic_variable:
                cmd = "x/" + word + "&" + v
                output = gdb.execute(cmd, to_string=True)
                var_addr = output.split()[0].strip()
                var_content = output.split(':')[1].strip()
                offset = hex(getoff("&" + v))
                to_print = '\033[34m%s\033[33m(%s)\033[37m' % (v, offset)
                to_print = to_print.ljust(36 + 15, ' ')
                to_print += '%s: \033[37m%s' % (var_addr, var_content)
                print(to_print)
            if libc_path:
                cmd = 'strings -t x {} | grep "/bin/sh"'.format(libc_path)
                binsh_off = subprocess.check_output(cmd, shell=True).decode('utf8').split()[0]
                binsh_addr = libc_base + int(binsh_off, 16)
                cmd = "x/" + word + hex(binsh_addr)
                binsh_content = gdb.execute(cmd, to_string=True).split(':')[1].strip()
                to_print = '\033[34m"/bin/sh"\033[33m(0x%s)\033[37m' % binsh_off
                to_print = to_print.ljust(36 + 15, ' ')
                to_print += '0x%x: \033[37m%s' % (binsh_addr, binsh_content)
                print(to_print)
                # print one gadget
                if path.isfile('/usr/local/bin/one_gadget'):
                    print("========== one gadget ==========")
                    system("one_gadget {}".format(libc_path))
        except:
            print("You need run the program first")

    def findsyscall(self):
        """ find the syscall gadget"""
        arch = getarch()
        start, end = codeaddr()
        if arch == "x86-64":
            gdb.execute("find 0x050f " + hex(start) + " " + hex(end))
        elif arch == "i386":
            gdb.execute("find 0x80cd " + hex(start) + " " + hex(end))
        elif arch == "arm":
            gdb.execute("find 0xbc80df00 " + hex(start) + " " + hex(end))
        elif arch == "aarch64":
            gdb.execute("find 0xd4000001 " + hex(start) + " " + hex(end))
        else:
            print("error")

    def got(self):
        """ Print the got table """
        processname = getprocname()
        if processname:
            cmd = "objdump -R "
            if iscplus:
                cmd += "--demangle "
            cmd += "\"" + processname + "\""
            got = subprocess.check_output(cmd, shell=True)[:-2].decode('utf8')
            print(got)
        else:
            print("No current process or executable file specified.")

    def dyn(self):
        """ Print dynamic section """
        processname = getprocname()
        if processname:
            dyn = subprocess.check_output("readelf -d \"" + processname + "\"", shell=True).decode('utf8')
            print(dyn)
        else:
            print("No current process or executable file specified.")

    def rop(self, *arg):
        """ ROPgadget """
        procname = getprocname()
        cmd = 'ROPgadget --binary "{}"'.format(procname)
        if procname:
            for s in arg:
                cmd += ' | grep "{}"'.format(s)
            subprocess.call(cmd, shell=True)
        else:
            print("No current process or executable file specified.")

    def findcall(self, *arg):
        """ Find some function call """
        (sym,) = normalize_argv(arg, 1)
        output = searchcall(sym)
        print(output)

    def bcall(self, *arg):
        """ Set the breakpoint at some function call """
        (sym,) = normalize_argv(arg, 1)
        call = searchcall(sym)
        if "not found" in call:
            print("symbol not found")
        else:
            if ispie():
                codebaseaddr, codeend = codeaddr()
                for callbase in call.split('\n')[:-1]:
                    addr = int(callbase.split(':')[0], 16) + codebaseaddr
                    cmd = "b*" + hex(addr)
                    print(gdb.execute(cmd, to_string=True))
            else:
                for callbase in call.split('\n')[:-1]:
                    addr = int(callbase.split(':')[0], 16)
                    cmd = "b*" + hex(addr)
                    print(gdb.execute(cmd, to_string=True))


class PwngdbCmd(gdb.Command):
    """ Pwngdb command wrapper """

    def __init__(self):
        super(PwngdbCmd, self).__init__("pwngdb", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        self.dont_repeat()
        # Don't eval expression in PwngdbCmd commands
        arg = args.split()
        if len(arg) > 0:
            cmd = arg[0]
            if cmd in pwncmd.commands:
                func = getattr(pwncmd, cmd)
                func(*arg[1:])
            else:
                print("Unknown command")
        else:
            print("Unknown command")

        return


class PwngdbAlias(gdb.Command):
    """ Pwngdb Alias """

    def __init__(self, alias, command):
        self.command = command
        super(PwngdbAlias, self).__init__(alias, gdb.COMMAND_NONE)

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("%s %s" % (self.command, args))


def getarch():
    global capsize
    global word
    global arch
    data = gdb.execute('show arch', to_string=True)
    tmp = re.search("currently.*", data)
    if tmp:
        info = tmp.group()
        if "x86-64" in info:
            capsize = 8
            word = "gx "
            arch = "x86-64"
            return "x86-64"
        elif "aarch64" in info:
            capsize = 8
            word = "gx "
            arch = "aarch64"
            return "aarch64"
        elif "arm" in info:
            capsize = 4
            word = "wx "
            arch = "arm"
            return "arm"
        else:
            word = "wx "
            capsize = 4
            arch = "i386"
            return "i386"
    else:
        return "error"


def procmap():
    data = gdb.execute('info proc exe', to_string=True)
    pid = re.search('process.*', data)
    if pid:
        pid = pid.group()
        pid = pid.split()[1]
        maps = open("/proc/" + pid + "/maps", "r")
        infomap = maps.read()
        maps.close()
        return infomap
    else:
        return "error"


def iscplus():
    name = getprocname()
    data = subprocess.check_output(
        "readelf -s " + name, shell=True).decode('utf8')
    if "CXX" in data:
        return True
    else:
        return False


def getprocname(relative=False):
    procname = None
    try:
        data = gdb.execute("info proc exe", to_string=True)
        procname = re.search("exe.*", data).group().split("=")[1][2:-1]
    except:
        data = gdb.execute("info files", to_string=True)
        if data:
            procname = re.search('Symbols from "(.*)"', data).group(1)
    if procname and relative:
        return procname.split("/")[-1]
    return procname


def libcbase():
    infomap = procmap()
    data = re.search(".*libc.*\.so", infomap)
    if data:
        libcaddr = data.group().split("-")[0]
        gdb.execute("set $libc=%s" % hex(int(libcaddr, 16)))
        return int(libcaddr, 16)
    else:
        return 0


def ldbase():
    infomap = procmap()
    data = re.search(".*ld.*\.so", infomap)
    if data:
        ldaddr = data.group().split("-")[0]
        gdb.execute("set $ld=%s" % hex(int(ldaddr, 16)))
        return int(ldaddr, 16)
    else:
        return 0


def getheapbase():
    infomap = procmap()
    data = re.search(".*heap\]", infomap)
    if data:
        heapbase = data.group().split("-")[0]
        gdb.execute("set $heap=%s" % hex(int(heapbase, 16)))
        return int(heapbase, 16)
    else:
        return 0


def codeaddr():  # ret (start,end)
    infomap = procmap()
    procname = getprocname()
    pat = ".*" + procname
    data = re.findall(pat, infomap)
    if data:
        codebaseaddr = data[0].split("-")[0]
        codeend = data[0].split("-")[1].split()[0]
        gdb.execute("set $code=%s" % hex(int(codebaseaddr, 16)))
        return (int(codebaseaddr, 16), int(codeend, 16))
    else:
        return (0, 0)


def gettls():
    arch = getarch()
    if arch == "i386":
        vsysaddr = gdb.execute("info functions __kernel_vsyscall", to_string=True).split("\n")[-2].split()[0].strip()
        sysinfo = gdb.execute("searchmem " + vsysaddr, to_string=True)
        match = re.search(r"mapped : .*(0x[0-9a-z]{8})", sysinfo)
        if match:
            tlsaddr = int(match.groups()[0], 16) - 0x10
        else:
            return 0
        return tlsaddr
    elif arch == "x86-64":
        gdb.execute("call (int)arch_prctl(0x1003, $rsp-8)", to_string=True)
        data = gdb.execute("x/xg $rsp-8", to_string=True)
        return int(data.split(":")[1].strip(), 16)
    else:
        return 0


def getcanary():
    arch = getarch()
    tlsaddr = gettls()
    if not tlsaddr:
        return 'error'
    if arch == "i386":
        offset = 0x14
        result = gdb.execute("x/xw " + hex(tlsaddr + offset), to_string=True).split(":")[1].strip()
        return int(result, 16)
    elif arch == "x86-64":
        offset = 0x28
        result = gdb.execute("x/xg " + hex(tlsaddr + offset), to_string=True).split(":")[1].strip()
        return int(result, 16)
    else:
        return "error"


def getoff(sym):
    libc = libcbase()
    if type(sym) is int:
        return sym - libc
    else:
        try:
            data = gdb.execute("x/x " + sym, to_string=True)
            if "No symbol" in data:
                return 0
            else:
                data = re.search("0x.*[0-9a-f] ", data)
                data = data.group()
                symaddr = int(data[:-1], 16)
                return symaddr - libc
        except:
            return 0


def searchcall(sym):
    procname = getprocname()
    cmd = "objdump -d -M intel "
    if iscplus:
        cmd += "--demangle "
    cmd += "\"" + procname + "\""
    try:
        call = subprocess.check_output(cmd + "| grep \"call.*" + sym + "@plt>\"", shell=True).decode('utf8')
        return call
    except:
        return "symbol not found"


def ispie():
    procname = getprocname()
    result = subprocess.check_output("readelf -h " + "\"" + procname + "\"", shell=True).decode('utf8')
    if re.search("DYN", result):
        return True
    else:
        return False


def get_reg(reg):
    cmd = "info register " + reg
    result = int(gdb.execute(cmd, to_string=True).split()[1].strip(), 16)
    return result


def showfp(addr):
    if addr:
        cmd = "p *(struct _IO_FILE_plus *)" + hex(addr)
        try:
            result = gdb.execute(cmd)
        except:
            print("Can't not access 0x%x" % addr)
    else:
        print("You need to specify an address")


def showfpchain():
    getarch()
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


def testorange(addr):
    getarch()
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
                print("\033[;1;31m_wide_data->_IO_write_ptr(0x%x) < _wide_data->_IO_write_base(0x%x)\033[1;37m" % (
                w_write_ptr, w_write_base))
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


def testfsop(addr=None):
    getarch()
    if addr:
        cmd = "x/" + word + hex(addr)
    else:
        cmd = "x/" + word + "&_IO_list_all"
    head = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
    chain = head
    print("---------- fp : 0x%x ----------" % chain)
    testorange(chain)
    try:
        while chain != 0:
            cmd = "x/" + word + "&((struct _IO_FILE_plus *)" + hex(chain) + ").file._chain"
            chain = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            if chain != 0:
                print("---------- fp : 0x%x ----------" % chain)
                testorange(chain)
    except:
        print("Chain is corrupted")


def getfmtarg(addr):
    if capsize == 0:
        getarch()
    if arch == "i386":
        start = get_reg("esp")
        idx = (addr - start) / 4
        print("The index of format argument : %d" % idx)
    elif arch == "x86-64":
        start = get_reg("rsp")
        idx = (addr - start) / 8 + 6
        print("The index of format argument : %d" % idx)
    else:
        print("Not support the arch")


pwncmd = PwnCmd()
PwngdbCmd()
for cmd in pwncmd.commands:
    PwngdbAlias(cmd, "pwngdb %s" % cmd)

gdb.execute("set print asm-demangle on")
