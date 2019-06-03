# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import gdb
import re
import copy
import struct
import os

# main_arena
main_arena = 0
main_arena_off = 0

# thread
thread_arena = 0
enable_thread = False
tcache_enable = False
tcache = None
tcache_max_bin = 0

# chunks
top = {}
fastbin_size = 13
fastbin = []
fastchunk = []  # save fastchunk address for chunkinfo check
tcache_entry = []
tcache_count = []
all_tcache_entry = []  # save tcache address for chunkinfo check
last_remainder = {}
unsortbin = []
smallbin = {}  # {size:bin}
largebin = {}
system_mem = 0x21000

# chunk recording
free_mem_area = {}  # using in parse
alloc_mem_area = {}
free_record = {}  # using in trace
all_record = []  # all malloc free record trace
                 # struct: malloc/free, start_addr, end_addr

# setting for tracing memory allocation
trace_largebin = True
in_memalign = False
in_realloc = False
print_overlap = True
DEBUG = True  # debug msg (free and malloc) if you want

# breakpoints for tracing
malloc_bp = None
free_bp = None
memalign_bp = None
realloc_bp = None

# architecture setting
capsize = 0
word = ""
arch = ""

# condition
bin_corrupt = False


def u32(data, fmt="<I"):
    return struct.unpack(fmt, data)[0]


def u64(data, fmt="<Q"):
    return struct.unpack(fmt, data)[0]


def init_angelheap():
    global alloc_mem_area
    global free_record
    global all_record

    dis_trace_malloc()
    alloc_mem_area = {}
    free_record = {}
    all_record = []


class Malloc_bp_ret(gdb.FinishBreakpoint):
    global alloc_mem_area
    global free_record

    def __init__(self, arg):
        gdb.FinishBreakpoint.__init__(self, gdb.newest_frame(), internal=True)
        self.silent = True
        self.arg = arg

    def stop(self):
        global arch
        global all_record
        chunk = {}
        if len(arch) == 0:
            get_arch()
        if arch == "x86-64":
            value = int(self.return_value)
        else:
            cmd = "info register $eax"
            value = int(gdb.execute(cmd, to_string=True).split()[1].strip(), 16)
        chunk["addr"] = value - capsize * 2
        if value == 0:
            return False

        cmd = "x/" + word + hex(chunk["addr"] + capsize)
        chunk["size"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8
        overlap, status = check_overlap(chunk["addr"], chunk["size"], alloc_mem_area)
        if overlap and status == "error":
            if DEBUG:
                print(
                    "\033[34m>--------------------------------------------------------------------------------------<\033[37m")
                msg = "\033[33mmalloc(0x%x)\033[37m" % self.arg
                print("%-40s = 0x%x \033[31m overlap detected !! (0x%x)\033[37m" % (
                    msg, chunk["addr"] + capsize * 2, overlap["addr"]))
                print(
                    "\033[34m>--------------------------------------------------------------------------------------<\033[37m")
            else:
                print("\033[31moverlap detected !! (0x%x)\033[37m" % overlap["addr"])
            del alloc_mem_area[hex(overlap["addr"])]
        else:
            if DEBUG:
                msg = "\033[33mmalloc(0x%x)\033[37m" % self.arg
                print("%-40s = 0x%x" % (msg, chunk["addr"] + capsize * 2))
        alloc_mem_area[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"], chunk["addr"] + chunk["size"], chunk))
        backtrace = gdb.execute('bt', to_string=True)
        all_record.append(
            ['malloc', chunk["addr"], chunk["addr"] + chunk["size"], '\n'.join(backtrace.split('\n')[:-3])])
        if hex(chunk["addr"]) in free_record:
            free_chunk_tuple = free_record[hex(chunk["addr"])]
            free_chunk = free_chunk_tuple[2]
            split_chunk = {}
            del free_record[hex(chunk["addr"])]
            if chunk["size"] != free_chunk["size"]:
                split_chunk["addr"] = chunk["addr"] + chunk["size"]
                split_chunk["size"] = free_chunk["size"] - chunk["size"]
                free_record[hex(split_chunk["addr"])] = copy.deepcopy(
                    (split_chunk["addr"], split_chunk["addr"] + split_chunk["size"], split_chunk))
        if self.arg >= 128 * capsize:
            Malloc_consolidate()


class Malloc_Bp_handler(gdb.Breakpoint):
    def stop(self):
        global arch
        if len(arch) == 0:
            get_arch()
        if arch == "x86-64":
            reg = "$rdi"
        else:
            # for _int_malloc in x86's glibc (unbuntu 14.04 & 16.04), size is stored in edx
            # fbi warning!
            # to be changed here!
            reg = "$edx"
        arg = int(gdb.execute("info register " + reg, to_string=True).split()[1].strip(), 16)
        Malloc_bp_ret(arg)
        return False


class Free_bp_ret(gdb.FinishBreakpoint):
    def __init__(self):
        gdb.FinishBreakpoint.__init__(self, gdb.newest_frame(), internal=True)
        self.silent = True

    def stop(self):
        Malloc_consolidate()
        return False


class Free_Bp_handler(gdb.Breakpoint):
    def stop(self):
        global alloc_mem_area
        global free_record
        global in_memalign
        global in_realloc
        global arch
        global all_record
        get_top_lastremainder()

        if len(arch) == 0:
            get_arch()
        if arch == "x86-64":
            reg = "$rdi"
            result = int(gdb.execute("info register " + reg, to_string=True).split()[1].strip(), 16)
        else:
            # for _int_free in x86's glibc (unbuntu 14.04 & 16.04), chunk address is stored in edx
            # fbi warning!
            # to be changed here!
            reg = "$edx"
            result = int(gdb.execute("info register " + reg, to_string=True).split()[1].strip(), 16)
        chunk = {}
        if in_memalign or in_realloc:
            Update_alloca()
            in_memalign = False
            in_realloc = False
        prev_freed = False
        chunk["addr"] = result - capsize * 2

        cmd = "x/" + word + hex(chunk["addr"] + capsize)
        size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        chunk["size"] = size & 0xfffffffffffffff8
        if (size & 1) == 0:
            prev_freed = True

        backtrace = gdb.execute('bt', to_string=True)
        all_record.append(['free', chunk["addr"], chunk["addr"] + chunk["size"], '\n'.join(backtrace.split('\n')[:-3])])

        overlap, status = check_overlap(chunk["addr"], chunk["size"], free_record)
        if overlap and status == "error":
            if DEBUG:
                msg = "\033[32mfree(0x%x)\033[37m (size = 0x%x)" % (result, chunk["size"])
                print(
                    "\033[34m>--------------------------------------------------------------------------------------<\033[37m")
                print("%-25s \033[31m double free detected !! (0x%x(size:0x%x))\033[37m" % (
                    msg, overlap["addr"], overlap["size"]))
                print(
                    "\033[34m>--------------------------------------------------------------------------------------<\033[37m",
                    end="")
            else:
                print("\033[31mdouble free detected !! (0x%x)\033[37m" % overlap["addr"])
            del free_record[hex(overlap["addr"])]
        else:
            if DEBUG:
                msg = "\033[32mfree(0x%x)\033[37m" % result
                print("%-40s (size = 0x%x)" % (msg, chunk["size"]), end="")

        if chunk["size"] <= 0x80:
            free_record[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"], chunk["addr"] + chunk["size"], chunk))
            if DEBUG:
                print("")
            if hex(chunk["addr"]) in alloc_mem_area:
                del alloc_mem_area[hex(chunk["addr"])]
            return False

        prev_chunk = {}
        if prev_freed:
            cmd = "x/" + word + hex(chunk["addr"])
            prev_chunk["size"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8
            prev_chunk["addr"] = chunk["addr"] - prev_chunk["size"]
            if hex(prev_chunk["addr"]) not in free_record:
                print("\033[31m confuse in prev_chunk 0x%x" % prev_chunk["addr"])
            else:
                prev_chunk["size"] += chunk["size"]
                del free_record[hex(prev_chunk["addr"])]

        next_chunk = {"addr": chunk["addr"] + chunk["size"]}

        if next_chunk["addr"] == top["addr"]:
            if hex(chunk["addr"]) in alloc_mem_area:
                del alloc_mem_area[hex(chunk["addr"])]
                Free_bp_ret()
            if DEBUG:
                print("")
            return False

        cmd = "x/" + word + hex(next_chunk["addr"] + capsize)
        next_chunk["size"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8
        cmd = "x/" + word + hex(next_chunk["addr"] + next_chunk["size"] +
                                capsize)
        next_inuse = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 1

        if next_inuse == 0 and prev_freed:  # next chunk is freed
            if hex(next_chunk["addr"]) not in free_record:
                print("\033[31m confuse in next_chunk 0x%x" % next_chunk["addr"])
            else:
                prev_chunk["size"] += next_chunk["size"]
                del free_record[hex(next_chunk["addr"])]
        if next_inuse == 0 and not prev_freed:
            if hex(next_chunk["addr"]) not in free_record:
                print("\033[31m confuse in next_chunk 0x%x" % next_chunk["addr"])
            else:
                chunk["size"] += next_chunk["size"]
                del free_record[hex(next_chunk["addr"])]
        if prev_freed:
            if hex(chunk["addr"]) in alloc_mem_area:
                del alloc_mem_area[hex(chunk["addr"])]
            chunk = prev_chunk

        if DEBUG:
            print("")
        free_record[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"], chunk["addr"] + chunk["size"], chunk))
        if hex(chunk["addr"]) in alloc_mem_area:
            del alloc_mem_area[hex(chunk["addr"])]
        if chunk["size"] > 65536:
            Malloc_consolidate()
        return False


class Memalign_Bp_handler(gdb.Breakpoint):
    def stop(self):
        global in_memalign
        in_memalign = True
        return False


class Realloc_Bp_handler(gdb.Breakpoint):
    def stop(self):
        global in_realloc
        in_realloc = True
        return False


def Update_alloca():
    global alloc_mem_area
    if capsize == 0:
        get_arch()
    for addr, (start, end, chunk) in alloc_mem_area.items():
        cmd = "x/" + word + hex(chunk["addr"] + capsize * 1)
        cur_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8

        if cur_size != chunk["size"]:
            chunk["size"] = cur_size
            alloc_mem_area[hex(chunk["addr"])] = copy.deepcopy((start, start + cur_size, chunk))


def Malloc_consolidate():
    """ merge fastbin when malloc a large chunk or free a very large chunk """
    global fastbin
    global free_record

    if capsize == 0:
        get_arch()
    free_record = {}
    if not get_heap_info():
        print("Can't find heap info")
        return
    free_record = copy.deepcopy(free_mem_area)


def get_arch():
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


def infoprocmap():
    """ Use gdb command 'info proc map' to get the memory mapping """
    """ Notice: No permission info """
    resp = gdb.execute("info proc map", to_string=True).split("\n")
    resp = '\n'.join(resp[i] for i in range(4, len(resp))).strip().split("\n")
    infomap = ""
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
        infomap += line
    return infomap


def procmap():
    data = gdb.execute('info proc exe', to_string=True)
    pid = re.search('process.*', data)
    if pid:
        pid = pid.group()
        pid = pid.split()[1]
        fpath = "/proc/" + pid + "/maps"
        if os.path.isfile(fpath):  # if file exist, read memory mapping directly from file
            maps = open(fpath)
            infomap = maps.read()
            maps.close()
            return infomap
        else:  # if file doesn't exist, use 'info proc map' to get the memory mapping
            return infoprocmap()
    else:
        return "error"


def libcbase():
    infomap = procmap()
    data = re.search(".*libc.*\.so", infomap)
    if data:
        libcaddr = data.group().split("-")[0]
        return int(libcaddr, 16)
    else:
        return 0


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


def set_thread_arena():
    global thread_arena
    global main_arena
    global enable_thread
    if capsize == 0:
        get_arch()
    try:
        data = gdb.execute("x/" + word + "&thread_arena", to_string=True)
    except:
        return
    enable_thread = True
    if "main_arena" in data:
        thread_arena = main_arena
        return
    thread_arena = int(data.split(":")[1].strip(), 16)


def set_main_arena():
    global main_arena
    global main_arena_off

    offset = getoff("&main_arena")
    if offset == 0:  # no main_arena symbol
        print(
            "Cannot get main_arena's symbol address. Make sure you install libc debug file (libc6-dbg & libc6-dbg:i386 for debian package).")
        return
    libc = libcbase()
    get_arch()
    main_arena_off = offset
    main_arena = libc + main_arena_off


def check_overlap(addr, size, data=None):
    if data:
        for key, (start, end, chunk) in data.items():
            if (addr >= start and addr < end) or ((addr + size) > start and (addr + size) < end) or (
                    (addr < start) and ((addr + size) >= end)):
                return chunk, "error"
    else:
        for key, (start, end, chunk) in free_mem_area.items():
            if (addr >= start and addr < end) or ((addr + size) > start and (addr + size) < end) or (
                    (addr < start) and
                    ((addr + size) >= end)):
                return chunk, "freed"
        for key, (start, end, chunk) in alloc_mem_area.items():
            if (addr >= start and addr < end) or ((addr + size) > start and (addr + size) < end) or (
                    (addr < start) and ((addr + size) >= end)):
                return chunk, "inused"
    return None, None


def get_top_lastremainder(arena=None):
    global fastbin_size
    global top
    global last_remainder
    if not arena:
        arena = main_arena
    chunk = {}
    if capsize == 0:
        get_arch()
    # get top
    cmd = "x/" + word + "&((struct malloc_state *)" + hex(arena) + ").top"
    chunk["addr"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
    chunk["size"] = 0
    if chunk["addr"]:
        cmd = "x/" + word + hex(chunk["addr"] + capsize * 1)
        try:
            chunk["size"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8
            if chunk["size"] > system_mem:
                chunk["memerror"] = "top is broken ?"
        except:
            chunk["memerror"] = "invaild memory"
    top = copy.deepcopy(chunk)
    # get last_remainder
    chunk = {}
    cmd = "x/" + word + "&((struct malloc_state *)" + hex(arena) + ").last_remainder"
    chunk["addr"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
    chunk["size"] = 0
    if chunk["addr"]:
        cmd = "x/" + word + hex(chunk["addr"] + capsize * 1)
        try:
            chunk["size"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8
        except:
            chunk["memerror"] = "invaild memory"
    last_remainder = copy.deepcopy(chunk)


def get_fast_bin(arena=None):
    global fastbin
    global fastchunk
    global fastbin_size
    global free_mem_area

    if not arena:
        arena = main_arena
    fastbin = []
    fastchunk = []
    # freememoryarea = []
    if capsize == 0:
        get_arch()
    cmd = "x/" + word + "&((struct malloc_state *)" + hex(arena) + ").fastbinsY"
    fastbinsY = int(gdb.execute(cmd, to_string=True).split(":")[0].split()[0].strip(), 16)
    for i in range(fastbin_size - 3):
        fastbin.append([])
        chunk = {}
        is_overlap = (None, None)
        cmd = "x/" + word + hex(fastbinsY + i * capsize)
        chunk["addr"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)

        while chunk["addr"] and not is_overlap[0]:
            cmd = "x/" + word + hex(chunk["addr"] + capsize * 1)
            try:
                chunk["size"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8
            except:
                chunk["memerror"] = "invaild memory"
                break
            is_overlap = check_overlap(chunk["addr"], (capsize * 2) * (i + 2))
            chunk["overlap"] = is_overlap
            free_mem_area[hex(chunk["addr"])] = copy.deepcopy(
                (chunk["addr"], chunk["addr"] + (capsize * 2) * (i + 2), chunk))
            fastbin[i].append(copy.deepcopy(chunk))
            fastchunk.append(chunk["addr"])
            cmd = "x/" + word + hex(chunk["addr"] + capsize * 2)
            chunk = {}
            chunk["addr"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        if not is_overlap[0]:
            chunk["size"] = 0
            chunk["overlap"] = None
            fastbin[i].append(copy.deepcopy(chunk))


def get_curthread():
    cmd = "thread"
    thread_id = int(gdb.execute(cmd, to_string=True).split("thread is")[1].split()[0].strip())
    return thread_id


def get_all_threads():
    cmd = "info threads"
    all_threads = [int(line.split()[0].strip()) for line in
                   gdb.execute(cmd, to_string=True).replace("*", "").split("\n")[1:-1]]
    return all_threads


def thread_cmd_execute(thread_id, thread_cmd):
    cmd = "thread apply %d %s" % (thread_id, thread_cmd)
    result = gdb.execute(cmd, to_string=True)
    return result


def get_tcache():
    global tcache
    global tcache_enable
    global tcache_max_bin

    if capsize == 0:
        get_arch()
    try:
        tcache_max_bin = int(gdb.execute("x/" + word + " &mp_.tcache_bins", to_string=True).split(":")[1].strip(), 16)
        try:
            tcache_enable = True
            result = gdb.execute("x/" + word + "&tcache", to_string=True)
            tcache = int(result.split(":")[1].strip(), 16)
        except:
            heapbase = get_heapbase()
            if heapbase != 0:
                cmd = "x/" + word + hex(heapbase + capsize * 1)
                f_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
                while (f_size == 0):
                    heapbase += capsize * 2
                    cmd = "x/" + word + hex(heapbase + capsize * 1)
                    f_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
                tcache = heapbase + capsize * 2
            else:
                tcache = 0
    except:
        tcache_enable = False
        tcache = 0


def get_tcache_count():
    global tcache_count
    tcache_count = []
    if not tcache_enable:
        return
    if capsize == 0:
        arch = get_arch()
    count_size = int(tcache_max_bin / capsize)
    for i in range(count_size):
        cmd = "x/" + word + hex(tcache + i * capsize)
        c = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        for j in range(capsize):
            tcache_count.append((c >> j * 8) & 0xff)


def get_tcache_entry():
    global tcache_entry

    get_tcache()
    if not tcache_enable:
        return
    tcache_entry = []
    get_tcache_count()
    if capsize == 0:
        get_arch()
    if tcache and tcache_max_bin:
        entry_start = tcache + tcache_max_bin
        for i in range(tcache_max_bin):
            tcache_entry.append([])
            chunk = {}
            is_overlap = (None, None)
            cmd = "x/" + word + hex(entry_start + i * capsize)
            entry = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            while entry and not is_overlap[0]:
                chunk["addr"] = entry - capsize * 2
                cmd = "x/" + word + hex(chunk["addr"] + capsize)
                try:
                    chunk["size"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8
                except:
                    chunk["memerror"] = "invaild memory"
                    tcache_entry[i].append(copy.deepcopy(chunk))
                    break
                is_overlap = check_overlap(chunk["addr"], capsize * 2 * (i + 2))
                chunk["overlap"] = is_overlap
                free_mem_area[hex(chunk["addr"])] = copy.deepcopy(
                    (chunk["addr"], chunk["addr"] + (capsize * 2) * (i + 2), chunk))
                tcache_entry[i].append(copy.deepcopy(chunk))
                all_tcache_entry.append(chunk["addr"])
                cmd = "x/" + word + hex(chunk["addr"] + capsize * 2)
                chunk = {}
                entry = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)


def trace_normal_bin(chunkhead, arena=None):
    global free_mem_area
    if not arena:
        arena = main_arena
    libc = libcbase()
    bins = []
    if capsize == 0:
        get_arch()
    if chunkhead["addr"] == 0:  # main_arena not initial
        return None
    chunk = {}
    cmd = "x/" + word + hex(chunkhead["addr"] + capsize * 2)  # fd
    chunk["addr"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)  # get fd chunk
    if (chunk["addr"] == chunkhead["addr"]):  # no chunk in the bin
        if (chunkhead["addr"] > arena):
            return bins
        else:
            try:
                cmd = "x/" + word + hex(chunk["addr"] + capsize * 1)
                chunk["size"] = int(
                    gdb.execute(cmd, to_string=True).split(":")[1].strip(),
                    16) & 0xfffffffffffffff8
                is_overlap = check_overlap(chunk["addr"], chunk["size"])
                chunk["overlap"] = is_overlap
                chunk["memerror"] = "\033[31mbad fd (" + hex(
                    chunk["addr"]) + ")\033[37m"
            except:
                chunk["memerror"] = "invaild memory"
            bins.append(copy.deepcopy(chunk))
            return bins
    else:
        try:
            cmd = "x/" + word + hex(chunkhead["addr"] + capsize * 3)
            bk = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            cmd = "x/" + word + hex(bk + capsize * 2)
            bk_fd = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            if bk_fd != chunkhead["addr"]:
                chunkhead[
                    "memerror"] = "\033[31mdoubly linked list corruption {0} != {1} and \033[36m{2}\033[31m is broken".format(
                    hex(chunkhead["addr"]), hex(bk_fd), hex(chunkhead["addr"]))
                bins.append(copy.deepcopy(chunkhead))
                return bins
            fd = chunkhead["addr"]
            chunkhead = {}
            chunkhead["addr"] = bk  # bins addr
            chunk["addr"] = fd  # first chunk
        except:
            chunkhead["memerror"] = "invaild memory"
            bins.append(copy.deepcopy(chunkhead))
            return bins
        while chunk["addr"] != chunkhead["addr"]:
            try:
                cmd = "x/" + word + hex(chunk["addr"])
                chunk["prev_size"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(),
                                         16) & 0xfffffffffffffff8
                cmd = "x/" + word + hex(chunk["addr"] + capsize * 1)
                chunk["size"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8
            except:
                chunk["memerror"] = "invaild memory"
                break
            try:
                cmd = "x/" + word + hex(chunk["addr"] + capsize * 2)
                fd = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
                if fd == chunk["addr"]:
                    chunk["memerror"] = "\033[31mbad fd (" + hex(fd) + ")\033[37m"
                    bins.append(copy.deepcopy(chunk))
                    break
                cmd = "x/" + word + hex(fd + capsize * 3)
                fd_bk = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
                if chunk["addr"] != fd_bk:
                    chunk[
                        "memerror"] = "\033[31mdoubly linked list corruption {0} != {1} and \033[36m{2}\033[31m or \033[36m{3}\033[31m is broken".format(
                        hex(chunk["addr"]), hex(fd_bk), hex(fd), hex(chunk["addr"]))
                    bins.append(copy.deepcopy(chunk))
                    break
            except:
                chunk["memerror"] = "invaild memory"
                bins.append(copy.deepcopy(chunk))
                break
            is_overlap = check_overlap(chunk["addr"], chunk["size"])
            chunk["overlap"] = is_overlap
            free_mem_area[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"], chunk["addr"] + chunk["size"], chunk))
            bins.append(copy.deepcopy(chunk))
            cmd = "x/" + word + hex(chunk["addr"] + capsize * 2)  # find next
            chunk = {}
            chunk["addr"] = fd
    return bins


def get_unsortbin(arena=None):
    global unsortbin
    if not arena:
        arena = main_arena
    unsortbin = []
    if capsize == 0:
        get_arch()
    chunkhead = {}
    cmd = "x/" + word + "&((struct malloc_state *)" + hex(arena) + ").bins"
    chunkhead["addr"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
    unsortbin = trace_normal_bin(chunkhead, arena)


def get_smallbin(arena=None):
    global smallbin
    if not arena:
        arena = main_arena
    smallbin = {}
    if capsize == 0:
        get_arch()
    max_smallbin_size = 512 * int(capsize / 4)
    cmd = "x/" + word + "&((struct malloc_state *)" + hex(arena) + ").bins"
    bins_addr = int(gdb.execute(cmd, to_string=True).split(":")[0].split()[0].strip(), 16)
    for size in range(capsize * 4, max_smallbin_size, capsize * 2):
        chunkhead = {}
        idx = int((size / (capsize * 2))) - 1
        cmd = "x/" + word + hex(bins_addr + idx * capsize * 2)  # calc the smallbin index
        chunkhead["addr"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        try:
            bins = trace_normal_bin(chunkhead, arena)
        except:
            corruptbin = True
            bins = None
        if bins and len(bins) > 0:
            smallbin[hex(size)] = copy.deepcopy(bins)


def largbin_index(size):
    if capsize == 0:
        get_arch()
    if capsize == 8:
        if (size >> 6) <= 48:
            idx = 48 + (size >> 6)
        elif (size >> 9) <= 20:
            idx = 91 + (size >> 9)
        elif (size >> 12) <= 10:
            idx = 110 + (size >> 12)
        elif (size >> 15) <= 4:
            idx = 119 + (size >> 15)
        elif (size >> 18) <= 2:
            idx = 124 + (size >> 18)
        else:
            idx = 126
    else:
        if (size >> 6) <= 38:
            idx = 56 + (size >> 6)
        elif (size >> 9) <= 20:
            idx = 91 + (size >> 9)
        elif (size >> 12) <= 10:
            idx = 110 + (size >> 12)
        elif (size >> 15) <= 4:
            idx = 119 + (size >> 15)
        elif (size >> 18) <= 2:
            idx = 124 + (size >> 18)
        else:
            idx = 126
    return idx


def get_largebin(arena=None):
    global largebin
    global bin_corrupt
    if not arena:
        arena = main_arena
    largebin = {}
    if capsize == 0:
        get_arch()
    min_largebin = 512 * int(capsize / 4)
    cmd = "x/" + word + "&((struct malloc_state *)" + hex(arena) + ").bins"
    bins_addr = int(gdb.execute(cmd, to_string=True).split(":")[0].split()[0].strip(), 16)
    for idx in range(64, 128):
        chunkhead = {}
        cmd = "x/" + word + hex(bins_addr + idx * capsize * 2 - 2 * capsize)  # calc the largbin index
        chunkhead["addr"] = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        try:
            bins = trace_normal_bin(chunkhead, arena)
        except:
            bin_corrupt = True
            bins = None
        if bins and len(bins) > 0:
            largebin[idx] = copy.deepcopy(bins)


def get_system_mem(arena=None):
    global system_mem
    if not arena:
        arena = main_arena
    if capsize == 0:
        get_arch()
    cmd = "x/" + word + "&((struct malloc_state *)" + hex(arena) + ").system_mem"
    system_mem = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)


def get_heap_info(arena=None):
    global main_arena
    global thread_arena
    global free_mem_area
    global top
    global tcache_enable
    global tcache

    top = {}
    free_mem_area = {}
    corruptbin = False

    if arena:
        get_system_mem(arena)
        get_unsortbin(arena)
        get_smallbin(arena)
        if trace_largebin:
            get_largebin(arena)
        get_fast_bin(arena)
        get_top_lastremainder(arena)
        get_tcache_entry()
        return True

    set_main_arena()
    set_thread_arena()
    if thread_arena and enable_thread:
        get_system_mem(thread_arena)
        get_unsortbin(thread_arena)
        get_smallbin(thread_arena)
        if trace_largebin:
            get_largebin(thread_arena)
        get_fast_bin(thread_arena)
        get_top_lastremainder(thread_arena)
        get_tcache_entry()
        return True

    elif main_arena and not enable_thread:
        get_system_mem()
        get_unsortbin()
        get_smallbin()
        if trace_largebin:
            get_largebin()
        get_fast_bin()
        get_top_lastremainder()
        get_tcache_entry()
        return True
    return False


def get_reg(reg):
    cmd = "info register " + reg
    result = int(gdb.execute(cmd, to_string=True).split()[1].strip(), 16)
    return result


def trace_malloc():
    global malloc_bp
    global free_bp
    global memalign_bp
    global realloc_bp

    malloc_bp = Malloc_Bp_handler("*" + "__libc_malloc")
    free_bp = Free_Bp_handler("*" + "__libc_free")
    memalign_bp = Memalign_Bp_handler("*" + "__libc_memalign")
    realloc_bp = Realloc_Bp_handler("*" + "__libc_realloc")
    if not get_heap_info():
        print("Can't find heap info")
        return


def dis_trace_malloc():
    global malloc_bp
    global free_bp
    global memalign_bp
    global realloc_bp

    if malloc_bp:
        malloc_bp.delete()
        malloc_bp = None
    if free_bp:
        free_bp.delete()
        free_bp = None
    if memalign_bp:
        memalign_bp.delete()
        memalign_bp = None
    if realloc_bp:
        realloc_bp.delete()
        realloc_bp = None


def find_overlap(chunk, bins):
    is_overlap = False
    count = 0
    for current in bins:
        if chunk["addr"] == current["addr"]:
            count += 1
    if count > 1:
        is_overlap = True
    return is_overlap


def unlinkable(chunkaddr, fd=None, bk=None):
    if capsize == 0:
        get_arch()
    try:
        cmd = "x/" + word + hex(chunkaddr + capsize)
        chunk_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16) & 0xfffffffffffffff8
        cmd = "x/" + word + hex(chunkaddr + chunk_size)
        next_prev_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        if not fd:
            cmd = "x/" + word + hex(chunkaddr + capsize * 2)
            fd = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        if not bk:
            cmd = "x/" + word + hex(chunkaddr + capsize * 3)
            bk = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(fd + capsize * 3)
        fd_bk = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(bk + capsize * 2)
        bk_fd = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        if chunk_size != next_prev_size:
            print(
                "\033[32mUnlinkable :\033[1;31m False (corrupted size chunksize(0x%x) != prev_size(0x%x)) ) \033[37m " % (
                    chunk_size, next_prev_size))
        elif (chunkaddr == fd_bk) and (chunkaddr == bk_fd):
            print("\033[32mUnlinkable :\033[1;33m True\033[37m")
            print("\033[32mResult of unlink :\033[37m")
            print(
                "\033[32m      \033[1;34m FD->bk (\033[1;33m*0x%x\033[1;34m) = BK (\033[1;37m0x%x ->\033[1;33m 0x%x\033[1;34m)\033[37m " % (
                    fd + capsize * 3, fd_bk, bk))
            print(
                "\033[32m      \033[1;34m BK->fd (\033[1;33m*0x%x\033[1;34m) = FD (\033[1;37m0x%x ->\033[1;33m 0x%x\033[1;34m)\033[37m " % (
                    bk + capsize * 2, bk_fd, fd))
        else:
            if chunkaddr != fd_bk:
                print("\033[32mUnlinkable :\033[1;31m False (FD->bk(0x%x) != (0x%x)) \033[37m " % (fd_bk, chunkaddr))
            else:
                print("\033[32mUnlinkable :\033[1;31m False (BK->fd(0x%x) != (0x%x)) \033[37m " % (bk_fd, chunkaddr))
    except:
        print("\033[32mUnlinkable :\033[1;31m False (FD or BK is corruption) \033[37m ")


def freeable(victim):
    global fastchunk
    global system_mem
    if capsize == 0:
        get_arch()
    chunkaddr = victim
    try:
        if not get_heap_info():
            print("Can't find heap info")
            return
        cmd = "x/" + word + hex(chunkaddr)
        prev_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(chunkaddr + capsize * 1)
        size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(chunkaddr + capsize * 2)
        fd = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(chunkaddr + capsize * 3)
        bk = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        prev_inuse = size & 1
        is_mmapd = (size >> 1) & 1
        non_main_arena = (size >> 2) & 1
        size = size & 0xfffffffffffffff8
        if is_mmapd:
            block = chunkaddr - prev_size
            total_size = prev_size + size
            if ((block | total_size) & (0xfff)) != 0:
                print(
                    "\033[32mFreeable :\033[1;31m False -> Invalid pointer (((chunkaddr(0x%x) - prev_size(0x%x))|(prev_size(0x%x) + size(0x%x)))) & 0xfff != 0 \033[37m" % (
                        chunkaddr, prev_size, prev_size, size))
                return
        else:
            if chunkaddr > (2 ** (capsize * 8) - (size & 0xfffffffffffffff8)):
                print(
                    "\033[32mFreeable :\033[1;31m False -> Invalid pointer chunkaddr (0x%x) > -size (0x%x)\033[37m" % (
                        chunkaddr, (2 ** (capsize * 8) - (size & 0xfffffffffffffff8))))
                return
            if (chunkaddr & (capsize * 2 - 1)) != 0:
                print(
                    "\033[32mFreeable :\033[1;31m False -> Invalid pointer misaligned chunkaddr (0x%x) & (0x%x) != 0\033[37m" % (
                        chunkaddr, (capsize * 2 - 1)))
                return
            if (size < capsize * 4):
                print(
                    "\033[32mFreeable :\033[1;31m False -> Chunkaddr (0x%x) invalid size (size(0x%x) < 0x%x )\033[37m" % (
                        chunkaddr, size, capsize * 4))
                return
            if (size & (capsize)) != 0:
                print(
                    "\033[32mFreeable :\033[1;31m False -> Chunkaddr (0x%x) invalid size (size(0x%x) & 0x%x != 0 )\033[37m" % (
                        chunkaddr, size, capsize))
                return
            cmd = "x/" + word + hex(chunkaddr + size + capsize)
            nextsize = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            nextchunk = chunkaddr + size
            status = nextsize & 1
            if size <= capsize * 0x10:  # fastbin
                if nextsize < capsize * 4:
                    print(
                        "\033[32mFreeable :\033[1;31m False -> Chunkaddr (0x%x) invalid next size (size(0x%x) < 0x%x )\033[37m" % (
                            chunkaddr, size, capsize * 4))
                    return
                if nextsize >= system_mem:
                    print(
                        "\033[32mFreeable :\033[1;31m False -> Chunkaddr (0x%x) invalid next size (size(0x%x) > system_mem(0x%x) )\033[37m" % (
                            chunkaddr, size, system_mem))
                    return
                old = fastbin[int(size / 0x10) - 2][0]["addr"]
                if chunkaddr == old:
                    print("\033[32mFreeable :\033[1;31m false -> Double free chunkaddr(0x%x) == 0x%x )\033[37m" % (
                        chunkaddr, old))
                    return
            else:
                if chunkaddr == top["addr"]:
                    print("\033[32mFreeable :\033[1;31m False -> Free top chunkaddr(0x%x) == 0x%x )\033[37m" % (
                        chunkaddr, top["addr"]))
                    return
                cmd = "x/" + word + hex(top["addr"] + capsize)
                topsize = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
                if nextchunk >= top["addr"] + topsize:
                    print("\033[32mFreeable :\033[1;31m False -> Out of top chunkaddr(0x%x) > 0x%x )\033[37m" % (
                        chunkaddr, top["addr"] + topsize))
                    return
                if status == 0:
                    print(
                        "\033[32mFreeable :\033[1;31m false -> Double free chunkaddr(0x%x) inused bit is not seted )\033[37m" % (
                            chunkaddr))
                    return
                if nextsize < capsize * 4:
                    print(
                        "\033[32mFreeable :\033[1;31m False -> Chunkaddr (0x%x) invalid next size (size(0x%x) < 0x%x )\033[37m" % (
                            chunkaddr, size, capsize * 4))
                    return
                if nextsize >= system_mem:
                    print(
                        "\033[32mFreeable :\033[1;31m False -> Chunkaddr (0x%x) invalid next size (size(0x%x) > system_mem(0x%x) )\033[37m" % (
                            chunkaddr, size, system_mem))
                    return
                if not prev_inuse:
                    cmd = "x/" + word + hex(chunkaddr - prev_size + capsize)
                    prev_chunk_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(),
                                          16) & 0xfffffffffffffff8
                    if prev_size != prev_chunk_size:
                        print("\033[32mFreeable :\033[1;31m False -> p->size(0x%x) != next->prevsize(0x%x) \033[37m" % (
                        prev_chunk_size, prev_size))
                        return

                if len(unsortbin) > 0:
                    bck = unsortbin[0]["addr"]
                    cmd = "x/" + word + hex(bck + capsize * 2)
                    fwd = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
                    cmd = "x/" + word + hex(fwd + capsize * 3)
                    bk = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
                    if bk != bck:
                        print(
                            "\033[32mFreeable :\033[1;31m False -> Corrupted unsorted chunkaddr fwd->bk(0x%x) != bck(0x%x) )\033[37m" % (
                                bk, bck))
                        return
            print("\033[32mFreeable :\033[1;33m True\033[37m")
    except:
        print("Can't access memory")


def get_heapbase():
    if (main_arena and not enable_thread) or thread_arena == main_arena:
        heapbase = int(gdb.execute("x/" + word + " &mp_.sbrk_base", to_string=True).split(":")[1].strip(), 16)
    elif thread_arena:
        arena_size = int(gdb.execute("p sizeof(main_arena)", to_string=True).split("=")[1].strip(), 16)
        heapbase = thread_arena + arena_size
    else:
        return None
    return heapbase


def chunkinfo(victim):
    global fastchunk

    if capsize == 0:
        get_arch()
    chunkaddr = victim
    try:
        if not get_heap_info():
            print("Can't find heap info")
            return
        cmd = "x/" + word + hex(chunkaddr)
        prev_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(chunkaddr + capsize * 1)
        size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(chunkaddr + capsize * 2)
        fd = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(chunkaddr + capsize * 3)
        bk = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(chunkaddr + (size & 0xfffffffffffffff8) + capsize)
        nextsize = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        status = nextsize & 1
        print("==================================")
        print("            Chunk info            ")
        print("==================================")
        if status:
            if chunkaddr in fastchunk:
                print("\033[1;32mStatus : \033[1;34m Freed (fast) \033[37m")
            elif chunkaddr in all_tcache_entry:
                print("\033[1;32mStatus : \033[1;34m Freed (tcache) \033[37m")
            else:
                print("\033[1;32mStatus : \033[31m Used \033[37m")
        else:
            print("\033[1;32mStatus : \033[1;34m Freed \033[37m")
            unlinkable(chunkaddr, fd, bk)
        freeable(chunkaddr)
        print("\033[32mprev_size :\033[37m 0x%x                  " % prev_size)
        print("\033[32msize :\033[37m 0x%x                  " % (size & 0xfffffffffffffff8))
        print("\033[32mprev_inused :\033[37m %x                    " % (size & 1))
        print("\033[32mis_mmap :\033[37m %x                    " % (size & 2))
        print("\033[32mnon_mainarea :\033[37m %x                     " % (size & 4))
        if not status:
            print("\033[32mfd :\033[37m 0x%x                  " % fd)
            print("\033[32mbk :\033[37m 0x%x                  " % bk)
        if size >= 512 * (capsize / 4):
            cmd = "x/" + word + hex(chunkaddr + capsize * 4)
            fd_nextsize = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            cmd = "x/" + word + hex(chunkaddr + capsize * 5)
            bk_nextsize = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            print("\033[32mfd_nextsize :\033[37m 0x%x  " % fd_nextsize)
            print("\033[32mbk_nextsize :\033[37m 0x%x  " % bk_nextsize)
    except:
        print("Can't access memory")


def freeptr(ptr):
    if capsize == 0:
        get_arch()
    freeable(ptr - capsize * 2)


def chunkptr(ptr):
    if capsize == 0:
        get_arch()
    chunkinfo(ptr - capsize * 2)


def mergeinfo(victim):
    global fastchunk

    if capsize == 0:
        get_arch()
    chunkaddr = victim
    try:
        if not get_heap_info():
            print("Can't find heap info")
            return
        print("==================================")
        print("            Merge info            ")
        print("==================================")
        cmd = "x/" + word + hex(chunkaddr)
        prev_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(chunkaddr + capsize * 1)
        size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        cmd = "x/" + word + hex(chunkaddr + (size & 0xfffffffffffffff8) + capsize)
        nextsize = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
        status = nextsize & 1
        if status:
            if chunkaddr in fastchunk:
                print("The chunk is freed")
            else:
                if (size & 0xfffffffffffffff8) <= 0x80:
                    print("The chunk will be a\033[32m fastchunk\033[37m")
                else:
                    prev_status = size & 1
                    next_chunk = chunkaddr + (size & 0xfffffffffffffff8)
                    cmd = "x/" + word + hex(next_chunk + (nextsize & 0xfffffffffffffff8) + capsize)
                    if next_chunk != top["addr"]:
                        next_nextsize = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
                        next_status = next_nextsize & 1
                    if not prev_status:  # if prev chunk is freed
                        prev_chunk = chunkaddr - prev_size
                        if next_chunk == top["addr"]:  # if next chunk is top
                            print("The chunk will merge into top , top will be \033[1;33m0x%x\033[37m " % prev_chunk)
                            print("\033[32mUnlink info : \033[1;33m0x%x\033[37m" % prev_chunk)
                            unlinkable(prev_chunk)
                        elif not next_status:  # if next chunk is freed
                            print("The chunk and \033[1;33m0x%x\033[0m will merge into \033[1;33m0x%x\033[37m" % (
                                next_chunk, prev_chunk))
                            print("\033[32mUnlink info : \033[1;33m0x%x\033[37m" % prev_chunk)
                            unlinkable(prev_chunk)
                            print("\033[32mUnlink info : \033[1;33m0x%x\033[37m" % next_chunk)
                            unlinkable(next_chunk)
                        else:
                            print("The chunk will merge into \033[1;33m0x%x\033[37m" % prev_chunk)
                            print("\033[32mUnlink info : \033[1;33m0x%x\033[37m" % prev_chunk)
                            unlinkable(prev_chunk)
                    else:
                        if next_chunk == top["addr"]:  # if next chunk is top
                            print("The chunk will merge into top , top will be \033[1;34m0x%x\033[37m" % chunkaddr)
                        elif not next_status:  # if next chunk is freed
                            print("The chunk will merge with \033[1;33m0x%x\033[37m" % next_chunk)
                            print("\033[32mUnlink info : \033[1;33m0x%x\033[37m" % next_chunk)
                            unlinkable(next_chunk)
                        else:
                            print("The chunk will not merge with other")
        else:
            print("The chunk is freed")
    except:
        print("Can't access memory")


def force(target):
    if capsize == 0:
        get_arch()
    if not get_heap_info():
        print("Can't find heap info")
        return
    if target % capsize != 0:
        print("Not alignment")
    else:
        nb = target - top["addr"] - capsize * 2
        print("nb = %d" % nb)


def putfastbin(arena=None):
    if capsize == 0:
        get_arch()

    if not get_heap_info(arena):
        print("Can't find heap info")
        return False
    for i, bins in enumerate(fastbin):
        cursize = (capsize * 2) * (i + 2)
        print("\033[32m(0x%02x)     fastbin[%d]:\033[37m " % (cursize, i), end="")
        for chunk in bins:
            if "memerror" in chunk:
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"], chunk["memerror"]), end="")
            elif chunk["size"] != cursize and chunk["addr"] != 0:
                print("\033[36m0x%x (size error (0x%x))\033[37m" % (chunk["addr"], chunk["size"]), end="")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (
                    chunk["addr"], chunk["overlap"][0]["addr"], chunk["overlap"][1]), end="")
            elif chunk == bins[0]:
                print("\033[34m0x%x\033[37m" % chunk["addr"], end="")
            else:
                if print_overlap:
                    if find_overlap(chunk, bins):
                        print("\033[31m0x%x\033[37m" % chunk["addr"], end="")
                    else:
                        print("0x%x" % chunk["addr"], end="")
                else:
                    print("0x%x" % chunk["addr"], end="")
            if chunk != bins[-1]:
                print(" --> ", end="")
        print("")
    return True


def put_tcache():
    if not tcache_enable:
        return
    for i, entry in enumerate(tcache_entry):
        cursize = (capsize * 2) * (i + 2)
        if len(tcache_entry[i]) > 0:
            print(
                "\033[33;1m(0x%02x)   tcache_entry[%d]\033[32m(%d)\033[33;1m:\033[37m " % (cursize, i, tcache_count[i]),
                end="")
        elif tcache_count[i] > 0:
            print("\033[33;1m(0x%02x)   tcache_entry[%d]\033[31;1m(%d)\033[33;1m:\033[37m 0\n" % (
                cursize, i, tcache_count[i]), end="")
        for chunk in entry:
            if "memerror" in chunk:
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"] + capsize * 2, chunk["memerror"]), end="")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (
                    chunk["addr"] + capsize * 2, chunk["overlap"][0]["addr"], chunk["overlap"][1]), end="")
            elif chunk == entry[0]:
                print("\033[34m0x%x\033[37m" % (chunk["addr"] + capsize * 2), end="")
            else:
                if print_overlap:
                    if find_overlap(chunk, entry):
                        print("\033[31m0x%x\033[37m" % chunk["addr"], end="")
                    else:
                        print("0x%x" % (chunk["addr"] + capsize * 2), end="")
                else:
                    print("0x%x" % (chunk["addr"] + capsize * 2), end="")
            if chunk != entry[-1]:
                print(" --> ", end="")
        if len(tcache_entry[i]) > 0:
            print("")
    return True


def put_unsorted(pad=False):
    if pad:
        s = 'unsortbin'.rjust(21, ' ')
    else:
        s = 'unsortbin'
    print("\033[35m%s:\033[37m " % s, end="")
    if unsortbin and len(unsortbin) > 0:
        for chunk in unsortbin:
            if "memerror" in chunk:
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"], chunk["memerror"]), end="")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (
                    chunk["addr"], chunk["overlap"][0]["addr"], chunk["overlap"][1]), end="")
            elif chunk == unsortbin[-1]:
                print("\033[34m0x%x\033[37m \33[33m(size : 0x%x)\033[37m" % (chunk["addr"], chunk["size"]), end="")
            else:
                print("0x%x \33[33m(size : 0x%x)\033[37m" % (chunk["addr"], chunk["size"]), end="")
            if chunk != unsortbin[-1]:
                print(" <--> ", end="")
        print("")
    else:
        print(0)  # no chunk in unsortbin


def putheapinfo(arena=None):
    if capsize == 0:
        get_arch()
    if not putfastbin(arena):
        return
    if "memerror" in top:
        print("\033[35m %20s:\033[31m 0x%x \033[33m(size : 0x%x)\033[31m (%s)\033[37m " % (
            "top", top["addr"], top["size"], top["memerror"]))
    else:
        print("\033[35m %20s:\033[34m 0x%x \033[33m(size : 0x%x)\033[37m " % ("top", top["addr"], top["size"]))

    print("\033[35m %20s:\033[34m 0x%x \033[33m(size : 0x%x)\033[37m " % (
        "last_remainder", last_remainder["addr"], last_remainder["size"]))
    put_unsorted(True)

    for size, bins in smallbin.items():
        idx = int((int(size, 16) / (capsize * 2))) - 2
        print("\033[33m(0x%03x)  %s[%2d]:\033[37m " % (int(size, 16), "smallbin", idx), end="")
        for chunk in bins:
            if "memerror" in chunk:
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"], chunk["memerror"]), end="")
            elif chunk["size"] != int(size, 16):
                print("\033[36m0x%x (size error (0x%x))\033[37m" % (chunk["addr"], chunk["size"]), end="")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (
                    chunk["addr"], chunk["overlap"][0]["addr"], chunk["overlap"][1]), end="")
            elif chunk == bins[-1]:
                print("\033[34m0x%x\033[37m" % chunk["addr"], end="")
            else:
                print("0x%x " % chunk["addr"], end="")
            if chunk != bins[-1]:
                print(" <--> ", end="")
        print("")
    for idx, bins in largebin.items():
        print("\033[33m  %15s[%2d]:\033[37m " % ("largebin", idx - 64), end="")
        for chunk in bins:
            if "memerror" in chunk:
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"], chunk["memerror"]), end="")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (
                    chunk["addr"], chunk["overlap"][0]["addr"], chunk["overlap"][1]), end="")
            elif largbin_index(chunk["size"]) != idx:
                print(
                    "\033[31m0x%x (incorrect bin size :\033[36m 0x%x\033[31m)\033[37m" % (chunk["addr"], chunk["size"]),
                    end="")
            elif chunk == bins[-1]:
                print("\033[34m0x%x\033[37m \33[33m(size : 0x%x)\033[37m" % (chunk["addr"], chunk["size"]), end="")
            else:
                print("0x%x \33[33m(size : 0x%x)\033[37m" % (chunk["addr"], chunk["size"]), end="")
            if chunk != bins[-1]:
                print(" <--> ", end="")
        print("")
    if not arena:
        put_tcache()
    if bin_corrupt:
        print("\033[31m Some bins is corrupted !\033[37m")


def putarenainfo():
    set_main_arena()
    if capsize == 0:
        get_arch()
    cur_arena = 0
    if main_arena:
        try:
            if capsize == 4:
                nextoff = 0x10d * capsize + 0xc
            else:
                nextoff = 0x10d * capsize
            count = 0
            print("  Main Arena  ".center(50, "="))
            putheapinfo(main_arena)
            cur_arena = int(gdb.execute("x/" + word + hex(main_arena + nextoff), to_string=True).split(":")[1].strip(),
                            16)
            while cur_arena != main_arena:
                count += 1
                print(("  Arena " + str(count) + "  ").center(50, "="))
                putheapinfo(cur_arena)
                cur_arena = int(
                    gdb.execute("x/" + word + hex(cur_arena + nextoff), to_string=True).split(":")[1].strip(), 16)
        except:
            print("Memory Error (heap)")
    else:
        print("Can't find heap info ")


def putheapinfoall():
    cur_thread_id = get_curthread()
    all_threads = get_all_threads()
    for thread_id in all_threads:
        if thread_id == cur_thread_id:
            print("\033[33;1m" + ("  Thread " + str(thread_id) + "  ").center(50, "=") + "\033[0m", end="")
        else:
            print(("  Thread " + str(thread_id) + "  ").center(50, "="), end="")
        result = thread_cmd_execute(thread_id, "heapinfo")
        print(result.split("):")[1], end="")


def putinused():
    print("\033[33m %s:\033[37m " % "inused ", end="")
    for addr, (start, end, chunk) in alloc_mem_area.items():
        print("0x%x," % (chunk["addr"]), end="")
    print("")


def parse_heap(arena=None):
    if capsize == 0:
        get_arch()
    if not get_heap_info(arena):
        print("can't find heap info")
        return

    hb = get_heapbase()
    chunkaddr = hb
    if not chunkaddr:
        print("Can't find heap")
        return
    print('\033[1;33m{:<20}{:<20}{:<21}{:<20}{:<18}{:<18}\033[0m'.format('addr', 'prev', 'size', 'status', 'fd', 'bk'))
    while chunkaddr != top["addr"]:
        try:
            cmd = "x/" + word + hex(chunkaddr)
            prev_size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            cmd = "x/" + word + hex(chunkaddr + capsize * 1)
            size = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            cmd = "x/" + word + hex(chunkaddr + capsize * 2)
            if size == 0 and chunkaddr == hb:
                chunkaddr += capsize * 2
                continue
            fd = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            cmd = "x/" + word + hex(chunkaddr + capsize * 3)
            bk = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            cmd = "x/" + word + hex(chunkaddr + (size & 0xfffffffffffffff8) + capsize)
            nextsize = int(gdb.execute(cmd, to_string=True).split(":")[1].strip(), 16)
            status = nextsize & 1
            size = size & 0xfffffffffffffff8
            if size == 0:
                print("\033[31mCorrupt ?! \033[0m(size == 0) (0x%x)" % chunkaddr)
                break
            if status:
                if chunkaddr in fastchunk or chunkaddr in all_tcache_entry:
                    msg = "\033[1;34m Freed \033[0m"
                    print(
                        '0x{:<18x}0x{:<18x}0x{:<18x}{:<16}{:>18}{:>18}'.format(chunkaddr, prev_size, size, msg, hex(fd),
                                                                               "None"))
                else:
                    msg = "\033[31m Used \033[0m"
                    print(
                        '0x{:<18x}0x{:<18x}0x{:<18x}{:<16}{:>18}{:>18}'.format(chunkaddr, prev_size, size, msg, "None",
                                                                               "None"))
            else:
                msg = "\033[1;34m Freed \033[0m"
                print('0x{:<18x}0x{:<18x}0x{:<18x}{:<16}{:>18}{:>18}'.format(chunkaddr, prev_size, size, msg, hex(fd),
                                                                             hex(bk)))
            chunkaddr = chunkaddr + (size & 0xfffffffffffffff8)

            if chunkaddr > top["addr"]:
                print("\033[31mCorrupt ?!\033[0m")
                break
        except:
            print("Corrupt ?!")
            break


def fastbin_idx(size):
    if capsize == 0:
        get_arch()
    if capsize == 8:
        return (size >> 4) - 2
    else:
        return (size >> 3) - 2


def fake_fast(addr, size):
    if not get_heap_info():
        print("Can't find heap info")
        return
    result = []
    idx = fastbin_idx(size)
    chunk_size = size & 0xfffffffffffffff8
    start = addr - chunk_size
    chunk_data = gdb.selected_inferior().read_memory(start, chunk_size)
    for offset in range(chunk_size - 4):
        fake_size = u32(chunk_data[offset:offset + 4])
        if fastbin_idx(fake_size) == idx:
            if ((fake_size & 2 == 2) and (fake_size & 4 == 4)) or (fake_size & 4 == 0):
                padding = addr - (start + offset - capsize) - capsize * 2
                result.append((start + offset - capsize, padding))
    return result


def get_fake_fast(addr, size=None):
    if capsize == 0:
        get_arch()
    fast_max = int(
        gdb.execute("x/" + word + "&global_max_fast",
                    to_string=True).split(":")[1].strip(), 16)
    if not fast_max:
        fast_max = capsize * 0x10
    if size:
        chunk_list = fake_fast(addr, size)
        for fakechunk in chunk_list:
            if len(chunk_list) > 0:
                print("\033[1;33mfake chunk : \033[1;0m0x{:<12x}\033[1;33m  padding :\033[1;0m {:<8d}".format(
                    fakechunk[0], fakechunk[1]))
    else:
        for i in range(int(fast_max / (capsize * 2) - 1)):
            size = capsize * 2 * 2 + i * capsize * 2
            chunk_list = fake_fast(addr, size)
            if len(chunk_list) > 0:
                print("-- size : %s --" % hex(size))
                for fakechunk in chunk_list:
                    print("\033[1;33mfake chunk :\033[1;0m 0x{:<12x}\033[1;33m  padding :\033[1;0m {:<8d}".format(
                        fakechunk[0], fakechunk[1]))


def check_heap(addr, print_num=4):
    addr = int(addr.cast(gdb.lookup_type('long')))
    if print_num == 'all':
        print_num = 0xffff
    print_num = int(print_num)
    count = 0
    found = False
    for record in reversed(all_record):
        if record[1] <= addr <= record[2]:
            found = True
            count += 1
            if count > print_num:
                break
            if record[0] == "malloc":
                print('================================== \033[1;32m', end='')  # green
            else:
                print('================================== \033[1;31m', end='')  # red
            print('{}\033[0;37m =================================='.format(record[0]))
            print("\033[32m" + 'start:' + "\033[37m", hex(record[1]))
            print("\033[32m" + 'end:  ' + "\033[37m", hex(record[2]))
            print('\033[34mbacktrace:\033[37m')
            print(record[3])
    if not found:
        print('\033[1;31mNot found!\033[0;37m')  # red
