source ~/peda/peda.py
source ~/pwngdb/gdbinit.py

define hookpost-run
python
import angelheap
angelheap.init_angelheap()
import gdbpwnpwnpwn
gdbpwnpwnpwn.init(False)
end
end

define hookpost-attach
python
import angelheap
angelheap.init_angelheap()
import gdbpwnpwnpwn
gdbpwnpwnpwn.init()
end
end
