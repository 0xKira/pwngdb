source ~/peda/peda.py
source ~/pwngdb/gdbinit.py

define init
python
angelheap.init_angelheap()
gdbpwnpwnpwn.init(False)
end
end

define hookpost-start
init
end

define hookpost-run
init
end

define hookpost-attach
python
angelheap.init_angelheap()
gdbpwnpwnpwn.init(True)
end
end
