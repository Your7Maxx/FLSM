#!/bin/python3

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import os

def print_event(cpu,data,size):
    event = b["events"].event(data)
    try:
        with open(f'/proc/{event.pid}/cmdline', 'r') as proc_cmd:
            proc_cmd = proc_cmd.read().rstrip()
    except:
        proc_cmd = ' '
    print("[Deny!] pid:{}  uid:{}  comm:{}\tcmdline:{}\tfile:{}".format(event.pid, event.uid, event.comm.decode(), proc_cmd, event.filename.decode()))
    print("-------------------------------------------------------------------------------")

def print_event1(cpu,data,size):
    event = b["events"].event(data)
    print("[*] data name: {}".format(event.name))
    print("[*] if match: {}".format(event.match))
    print("[*] offset: {}".format(event.offset))
    print("---" * 20)
    #print("[*] match:{}".format(event.match))

bpf_text = """
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/errno.h>
#include <linux/path.h>
#include <linux/dcache.h>

#define MAX_ENTRIES 10

struct data_t {
    char name[100];
    int match;
    int offset;
};

BPF_PERF_OUTPUT(events);

LSM_PROBE(file_open,struct file *file){

    int target_length = LENGTH ;
    char target_filename[] = NAME ;

    struct data_t data = {};
    struct dentry *dentry;

    dentry = file->f_path.dentry;
    data.match = 1;
    data.offset = 0;

    for(int i=1;i<MAX_ENTRIES;i++){
        bpf_probe_read_kernel_str(&data.name, sizeof(data.name), dentry->d_name.name);

        int dir_length = 0;
        for(dir_length; dir_length < sizeof(data.name); dir_length++){
            if (data.name[dir_length] == '\\0') break;
        }

        for(int j=0;j<dir_length;j++){
            if(target_filename[data.offset+j] != data.name[j]){
                data.match = 0;
                break;
            }
        }

        if(data.match && dentry != dentry->d_parent){
            data.offset = data.offset + dir_length;
            dentry = dentry->d_parent;
        }else{
            break;
        }

    }

    if(data.match){
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""

path = "/etc/passwd"
path_parts = path.split('/')
path_parts = [part for part in path_parts if part]
reversed_result = ''.join(path_parts[::-1])
path = '"' + reversed_result  + '"'


bpf_text = bpf_text.replace('LENGTH',str(len(reversed_result)))
bpf_text = bpf_text.replace('NAME', path)

b = BPF(text=bpf_text)
b["events"].open_perf_buffer(print_event1)

while 1:
    try:
        b.perf_buffer_poll()
       # b.trace_print()
    except KeyboardInterrupt:
        exit()

