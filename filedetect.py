#!/bin/python3

from bcc import BPF
import argparse
import os
from collections import defaultdict
from bcc.utils import printb


bpf_text = """
    #include <linux/fs.h>
    #include <linux/fs_struct.h>
    #include <linux/errno.h>
    #include <linux/path.h>
    #include <linux/dcache.h>

    #define MAX_ENTRIES 32

    struct data_t {
        u64 id;
        u32 uid;
        u32 pid;
        char comm[50];
        char name[200];
        char dir[100];
        int match;
        int file_flag;
        int end_flag;
    };

    BPF_PERF_OUTPUT(events);

    LSM_PROBE(file_open, struct file *file) {


        struct data_t data = {};
        struct dentry *dentry;
        struct dentry *dentry_p;

        dentry = file->f_path.dentry;
        dentry_p = dentry->d_parent;

        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        u64 tid_pid = bpf_get_current_pid_tgid();
        u32 pid = tid_pid >> 32;
        u32 tid = tid_pid;
        u32 uid = bpf_get_current_uid_gid();

        data.id = tid_pid;
        data.pid = pid;
        data.uid = uid;
        data.end_flag = 0;
        data.match = 1;
        data.file_flag = 0;

        bpf_probe_read_kernel(&data.name, sizeof(data.name), (void *)dentry->d_name.name);

        UID_FILTER
        PID_FILTER
        FILE_FILTER

        return 0;
    }
"""

raw_filename = ''
entries = defaultdict(list)

class FileMonitor:
    def __init__(self, bpf_text):
        self.bpf_text = bpf_text
        self.b = BPF(text=self.bpf_text)
        self.b["events"].open_perf_buffer(self.print_event)

    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)

        if not event.file_flag:
            if event.end_flag == 1 :
                paths = entries[event.id]
                paths.reverse()
                filename = os.path.join(*paths).decode()
                try:
                    del(entries[event.id])
                except Exception:
                    pass
                print("[Deny!] pid:{}  uid:{}  comm:{}  file:{}".format(event.pid, event.uid, event.comm.decode(),filename))
                print("--"*35)
            else:
                entries[event.id].append(event.name)
        else:
            filename = raw_filename
            print("[Deny!] pid:{}  uid:{}  comm:{}  file:{}".format(event.pid, event.uid, event.comm.decode(),filename))
            print("--"*35)




    def run(self):
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()

if __name__ == "__main__":

    examples = """examples:
    ./filedetect -p 181                 # All files whose pid is 181 are blocked from opening
    ./filedetect -u 1000                # All files whose uid is 100 are blocked from opening
    ./filedetect -f /path/to/file.test  # All files whose filename is /path/to/file.test are blocked from opening
"""

    parser = argparse.ArgumentParser(description="Use KRSI to customize blocking file operations.")

    parser.add_argument("-f", "--file", help="FILE to filter (e.g., /path/to/file.test)")
    parser.add_argument("-u", "--uid", help="UID to filter (e.g., 0/1000)")
    parser.add_argument("-p", "--pid", help="PID to filter (e.g., 123456)")
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()

    else:
        if args.uid:
            uid_text = """
                if(data.uid == %s){
                    if (data.name[0] != '/') {
                    int i;
                    for (i = 1; i < 10; i++) {

                        bpf_probe_read_kernel(&data.name, sizeof(data.name), (void *)dentry->d_name.name);
                        data.end_flag = 0;
                        events.perf_submit(ctx, &data, sizeof(data));

                        if (dentry == dentry->d_parent) {
                            break;
                        }

                        dentry = dentry->d_parent;
                    }
                }
                data.end_flag = 1;
                events.perf_submit(ctx, &data, sizeof(data));
                return -EPERM;
            }
            """ % args.uid
            bpf_text = bpf_text.replace('UID_FILTER',uid_text)
        else:
            bpf_text = bpf_text.replace('UID_FILTER', '')

        if args.pid:
            pid_text = """
                if(data.pid == %s){
                    if (data.name[0] != '/') {
                    int i;
                    for (i = 1; i < 10; i++) {

                        bpf_probe_read_kernel(&data.name, sizeof(data.name), (void *)dentry->d_name.name);
                        data.end_flag = 0;
                        events.perf_submit(ctx, &data, sizeof(data));

                        if (dentry == dentry->d_parent) {
                            break;
                        }

                        dentry = dentry->d_parent;
                    }
                }
                data.end_flag = 1;
                events.perf_submit(ctx, &data, sizeof(data));
                return -EPERM;
            }
            """ % args.pid
            bpf_text = bpf_text.replace('PID_FILTER',pid_text)
        else:
            bpf_text = bpf_text.replace('PID_FILTER', '')

        if args.file:
            raw_filename = str(args.file)
            dir_path, file_name = os.path.split(str(args.file))
            parent_dir, current_dir = os.path.split(dir_path)

            if not current_dir:
                current_dir = "/"

            FILELENGTH = str(len(file_name))
            DIRLENGTH = str(len(current_dir))

            file_name = '"' + file_name + '"'
            dir_path = '"' + current_dir + '"'

            file_text = """


                int target_file_length = FILELENGTH;
                int target_dir_length = DIRLENGTH;
                char target_filename[] = FILENAME;
                char target_dirname[] = DIRNAME;
                bpf_probe_read_kernel_str(&data.name, sizeof(data.name), dentry->d_name.name);
                bpf_probe_read_kernel_str(&data.dir, sizeof(data.dir), dentry_p->d_name.name);

                int len1 = 0;
                for(len1; len1 < sizeof(data.name); len1++){
                    if (data.name[len1] == '\\0') break;
                }

                int len2 = 0;
                for(len2; len2 < sizeof(data.dir); len2++){
                    if (data.dir[len2] == '\\0') break;
                }

                if(target_file_length != len1){
                    data.match = 0;
                }else{
                    for(int i=0;i<len1;i++){
                        if(target_filename[i] != data.name[i]){
                            data.match = 0;
                            break;
                        }
                    }
                }

                if(target_dir_length != len2){
                    data.match = 0;
                }else{
                    for(int j=0;j<len2;j++){
                        if(target_dirname[j] != data.dir[j]){
                            data.match = 0;
                            break;
                        }
                    }
                }

                if(data.match){
                    data.file_flag = 1;
                    events.perf_submit(ctx, &data, sizeof(data));
                    return -EPERM;
                }
            """
            file_text = file_text.replace('FILELENGTH', FILELENGTH)
            file_text = file_text.replace('DIRLENGTH', DIRLENGTH)
            file_text = file_text.replace('FILENAME', file_name)
            file_text = file_text.replace('DIRNAME', dir_path)

            bpf_text = bpf_text.replace('FILE_FILTER',file_text)

        else:
            bpf_text = bpf_text.replace('FILE_FILTER', '')

        file_monitor = FileMonitor(bpf_text)
        file_monitor.run()
