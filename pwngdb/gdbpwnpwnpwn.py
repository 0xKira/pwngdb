import gdb
import re
from subprocess import check_output, CalledProcessError, STDOUT

elf_base = 0
elf_base_old = 0
pid = 0
is_pie_on = False
proc_name = None


def set_current_pid():
    i = gdb.selected_inferior()
    if i is not None:
        global pid
        pid = i.pid
        return True
    return False


def set_elf_base(proc_name):
    global elf_base, elf_base_old
    elf_base_old = elf_base
    patt = re.compile(r'.*?([0-9a-f]+)\-[0-9a-f]+\s+r-xp.*?%s' % proc_name)
    vmmap = check_output(['cat', '/proc/%s/maps' % pid]).decode()
    elf_base = int(patt.findall(vmmap)[0], 16)
    print("\033[32m" + 'process base:' + "\033[37m", hex(elf_base))


def get_proc_name():
    global proc_name
    proc_name = None
    try:
        data = gdb.execute("info proc exe", to_string=True)
        proc_name = re.search("exe.*", data).group().split("=")[1][2:-1]
    except:
        data = gdb.execute("info files", to_string=True)
        if data:
            proc_name = re.search('Symbols from "(.*)"', data).group(1)
    return proc_name


def pie_on(proc_name):
    result = check_output("readelf -h " + "\"" + proc_name + "\"", shell=True).decode('utf8')
    if re.search("DYN", result):
        return True
    else:
        return False


def init():
    global proc_name, is_pie_on
    set_current_pid()
    proc_name = get_proc_name()
    if pie_on(proc_name):
        is_pie_on = True
        set_elf_base(proc_name)
    else:
        is_pie_on = False
    gdb.execute('getheap')
    gdb.execute('libc')
    if is_pie_on:
        # if existing some breakpoints, delete them and set new breakpoints
        if gdb.breakpoints():
            breakpoints = []
            for br in gdb.breakpoints():
                # won't delete symbol breakpoint
                find = re.findall('^\*((?:0x)?[0-9a-fA-F]+)$', br.location)
                if find:
                    location = int(find[0], 0)  # let python figure out the base
                    breakpoints.append(location - elf_base_old)
                    br.delete()
            for i in breakpoints:
                gdb.execute('b *%d' % (i + elf_base))


class ReattachCommand(gdb.Command):
    """
    Reattaches the new instance of the previous process.
    First argument is the name of executable (enough to specify the first time)
    """

    def __init__(self):
        super(ReattachCommand, self).__init__("ra", gdb.COMMAND_SUPPORT, gdb.COMPLETE_FILENAME)

    def invoke(self, arg, from_tty):
        global proc_name, pid, is_pie_on

        fn = arg.split(' ')[0].strip()
        if len(fn) > 0:
            proc_name = fn
        else:
            get_proc_name()
        if not proc_name:
            print('Please specify program name first!')
            return
        try:
            pid = check_output(["pidof", proc_name]).strip()
        except CalledProcessError as e:
            if e.returncode == 1:
                print('Process not found :(')
                return
            else:
                raise e

        pid = pid.decode().split(' ')[0]
        gdb.execute('attach ' + pid)


class PieBreak(gdb.Command):
    """ Break according to the offset to the elf base address """

    def __init__(self):
        super(PieBreak, self).__init__("bb", gdb.COMMAND_SUPPORT, gdb.COMPLETE_EXPRESSION)

    def invoke(self, arg, from_tty):
        offset = arg.split(' ')[0].strip()
        if len(offset) == 0:
            print('I need an offset:(')
            return
        if is_pie_on:
            gdb.execute('b *%d' % (int(gdb.parse_and_eval(offset).cast(gdb.lookup_type('long'))) + elf_base))
        else:
            gdb.execute('b *%d' % (gdb.parse_and_eval(offset)))


class PieExamineMem(gdb.Command):
    """ Examine memory according to the offset to the elf base address """

    def __init__(self):
        super(PieExamineMem, self).__init__("xx", gdb.COMMAND_SUPPORT, gdb.COMPLETE_EXPRESSION)

    def invoke(self, arg, from_tty):
        offset = arg.split(' ')[0].strip()
        if len(offset) == 0:
            print('I need an memory location:(')
            return
        if is_pie_on:
            gdb.execute('x{}+0x{:x}'.format(arg.rstrip(), elf_base))
        else:
            gdb.execute('x' + arg)


ReattachCommand()
PieBreak()
PieExamineMem()
