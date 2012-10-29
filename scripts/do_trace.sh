#!/bin/bash

# Post-process kmem events
#cat boot_kmem.log | ./post-process/addr2sym.py -m linux/System.map | ./post-process/trace2account.py > boot_kmem_account.log
./post-process/trace_analyze.py -f kmem.log -k ./linux -c acc_waste.txt -o waste -r rings_waste.png -a waste
./post-process/trace_analyze.py -f kmem.log -k ./linux -c acc_alloc_count.txt -o alloc_count -r rings_current_dynamic.png -a current_dynamic
./post-process/trace_analyze.py -f kmem.log -k ./linux -c acc_current.txt -o current_dynamic -r rings_static.png -a static
./post-process/trace_analyze.py -f kmem.log -k ./linux -r rings_current -a current

