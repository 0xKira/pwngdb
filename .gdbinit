source ~/peda/peda.py
source ~/pwngdb/pwngdb.py
source ~/pwngdb/AAApwn/gdbinit.py

define hook-run
python
import angelheap
angelheap.init_angelheap()
import gdbpwnpwnpwn
gdbpwnpwnpwn.init()
end
end
