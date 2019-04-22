source ~/peda/peda.py
source ~/pwngdb/pwngdb.py
source ~/pwngdb/pwngdb/gdbinit.py

define hook-run
python
import angelheap
angelheap.init_angelheap()
import gdbpwnpwnpwn
gdbpwnpwnpwn.init()
end
end

define hook-attach
python
import angelheap
angelheap.init_angelheap()
import gdbpwnpwnpwn
gdbpwnpwnpwn.init()
end
end
