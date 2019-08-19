source ~/peda/peda.py
source ~/pwngdb/gdbinit.py

define hookpost-run
python
angelheap.init_angelheap()
gdbpwnpwnpwn.init(False)
end
end

define hookpost-attach
python
angelheap.init_angelheap()
gdbpwnpwnpwn.init()
end
end
