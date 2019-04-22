source ~/peda/peda.py
source ~/pwngdb/pwngdb.py
source ~/pwngdb/pwngdb/gdbinit.py

define hookpost-run
python
import angelheap
angelheap.init_angelheap()
import gdbpwnpwnpwn
gdbpwnpwnpwn.init()
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
