source ~/peda/peda.py
source ~/pwngdb/gdbinit.py

define init
set $print_addr = $arg0
python
angelheap.init_angelheap()
output = gdb.parse_and_eval('$print_addr') == 1
gdbpwnpwnpwn.init(output)
end
end

define hookpost-start
init 0
end

define hookpost-run
init 0
end

define hookpost-attach
init 1
end
