import gdb
import re
from subprocess import check_output, CalledProcessError, STDOUT

elf_base = 0
elf_base_old = 0
pid = 0
is_pie_on = False
filename = None


def set_current_pid():
    i = gdb.selected_inferior()
    if i is not None:
        global pid
        pid = i.pid
        return True
    return False


def set_elf_base(filename):
    global elf_base, elf_base_old
    elf_base_old = elf_base
    patt = re.compile(r'.*?([0-9a-f]+)\-[0-9a-f]+\s+r-xp.*?%s' % filename)
    vmmap = check_output(['cat', '/proc/%s/maps' % pid]).decode()
    elf_base = int(patt.findall(vmmap)[0], 16)
    print("\033[32m" + 'process base address:' + "\033[37m", hex(elf_base))


def pie_on(filename):
    # wtf, check_output output is stderr?!
    sec = check_output(["checksec", filename], stderr=STDOUT).decode()
    print(sec)
    # print "checksec command not defined.Do you load peda or other similar libs?"
    for line in sec.split('\n'):
        if 'PIE:' in line:
            if 'enabled' in line.lower():
                return True
            return False


def init():
    global filename
    data = gdb.execute('info files', to_string=True)
    filename = re.findall("Symbols from \"(.*?)\"", data)[0]
    global is_pie_on
    if pie_on(filename):
        is_pie_on = True
    else:
        is_pie_on = False


class ReattachCommand(gdb.Command):
    """
    Reattaches the new instance of the previous process.
    First argument is the name of executable (enough to specify the first time)
    """

    def __init__(self):
        self.lastFn = ''
        super(ReattachCommand, self).__init__("ra", gdb.COMMAND_SUPPORT,
                                              gdb.COMPLETE_FILENAME)

    def invoke(self, arg, from_tty):
        args = arg.split(' ')
        fn = args[0].strip()
        if len(fn) > 0:
            global filename
            filename = self.lastFn = fn

        if len(self.lastFn) == 0:
            print(
                'You have to specify the name of the process (for pidof) for the first time (it will be cached for later)'
            )
            return

        global pid
        try:
            pid = check_output(["pidof", self.lastFn]).strip()
        except CalledProcessError as e:
            if e.returncode == 1:
                print('Process not found :(')
            else:
                raise e

        pid = pid.decode().split(' ')[0]
        gdb.execute('attach ' + pid)
        gdb.execute('heap')
        global is_pie_on
        if pie_on(self.lastFn):
            is_pie_on = True
            set_elf_base(self.lastFn)
            # if exsiting some breakpoints, delete them and set new breakpoints
            if gdb.breakpoints():
                breakpoints = []
                for br in gdb.breakpoints():
                    # won't delete symbol breakpoint
                    find = re.findall('^\*(\d+)$', br.location)
                    if find:
                        location = int(find[0])
                        breakpoints.append(location - elf_base_old)
                        br.delete()
                for i in breakpoints:
                    gdb.execute('b *%d' % (i + elf_base))
        else:
            is_pie_on = False


class PieBreak(gdb.Command):
    """ Break according to the offset to the elf base address """

    def __init__(self):
        super(PieBreak, self).__init__("bb", gdb.COMMAND_SUPPORT,
                                       gdb.COMPLETE_EXPRESSION)

    def invoke(self, arg, from_tty):
        offset = arg.split(' ')[0].strip()
        if len(offset) == 0:
            print('I need an offset:(')
            return
        if is_pie_on:
            set_current_pid()
            set_elf_base(filename)
            gdb.execute(
                'b *%d' %
                (int(gdb.parse_and_eval(offset).cast(gdb.lookup_type('long')))
                 + elf_base))
        else:
            gdb.execute('b *%d' % (gdb.parse_and_eval(offset)))


ReattachCommand()
PieBreak()
