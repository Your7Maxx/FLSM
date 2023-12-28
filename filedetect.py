#!/bin/python3

from bcc import BPF
import argparse
import os
from collections import defaultdict
from bcc.utils import printb


bpf_text_LSM = """

    #include <linux/fs.h>
    #include <linux/fs_struct.h>
    #include <linux/errno.h>
    #include <linux/path.h>
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>
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

        MYSELF_PID_FILTER
        UID_FILTER
        PID_FILTER
        COMM_FILTER
        FILE_FILTER

        return 0;
    }

"""

bpf_text_OPENAT = """

    #include <uapi/linux/openat2.h>
    #include <linux/sched.h>

    struct data_t {
        int filelen;
        u32 uid;
        u32 pid;
        char comm[50];
        char name[200];
    };

    BPF_PERF_OUTPUT(events);

    int monitor_openat(struct pt_regs *ctx, int dfd, const char __user * filename, struct open_how *how)
    {
        struct data_t data = { };

        u64 tid_pid = bpf_get_current_pid_tgid();
        u32 pid = tid_pid >> 32;
        u32 uid = bpf_get_current_uid_gid();
        data.pid = pid;
        data.uid = uid;

        if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0){
            bpf_probe_read(&data.name, sizeof(data.name), (void *)filename);
        }

        MYSELF_PID_FILTER
        UID_FILTER
        PID_FILTER
        COMM_FILTER
        FILE_FILTER

        return 0;
    }

"""

raw_filename = ''
entries = defaultdict(list)

class FileDetecter:
    def __init__(self, bpf_text):
        self.bpf_text = bpf_text
        self.b = BPF(text=self.bpf_text)
        self.b["events"].open_perf_buffer(self.print_event)

    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        try:
            with open(f'/proc/{event.pid}/cmdline', 'r') as proc_cmd:
                proc_cmd = proc_cmd.read().rstrip()
        except:
            proc_cmd = ' '

        if not event.file_flag:
            if event.end_flag == 1 :
                paths = entries[event.id]
                paths.reverse()
                filename = os.path.join(*paths).decode()
                try:
                    del(entries[event.id])
                except Exception:
                    pass
                print("[*] pid:{} uid:{} comm:{} cmdline:{} file:{}".format(event.pid, event.uid, event.comm.decode(), proc_cmd, filename))
                print("--"*45)
            else:
                entries[event.id].append(event.name)
        else:
            filename = raw_filename
            print("[*] pid:{} uid:{} comm:{} cmdline:{} file:{}".format(event.pid, event.uid, event.comm.decode(), proc_cmd, filename))
            print("--"*45)


    def run(self):
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()

class FileMonitor:
    def __init__(self, bpf_text):
        self.bpf_text = bpf_text
        self.b = BPF(text=self.bpf_text)
        self.b.attach_kprobe(event="do_sys_openat2", fn_name="monitor_openat")
        self.b["events"].open_perf_buffer(self.print_event)

    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        try:
            with open(f'/proc/{event.pid}/cmdline', 'r') as proc_cmd:
                proc_cmd = proc_cmd.read().rstrip()
        except:
            proc_cmd = ' '

        print("[*] pid:{} uid:{} comm:{} cmdline:{} file:{}".format(event.pid, event.uid, event.comm.decode(), proc_cmd, event.name))
        print("--"*45)

    def run(self):
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()


if __name__ == "__main__":

    examples = """examples:
    ./filedetect -a                            # All files are monitored from opening
    ./filedetect -p 181                        # All files whose pid is 181 are monitored from opening
    ./filedetect -u 1000                       # All files whose uid is 100 are monitored from opening
    ./filedetect -n python                     # All files whose comm is "python" are monitored from opening
    ./filedetect -f /path/to/file.test         # All files whose filename is /path/to/file.test are monitored from opening

    ./filedetect -p 181 --deny                 # All files whose pid is 181 are blocked from opening
    ./filedetect -u 1000 --deny                # All files whose uid is 100 are blocked from opening
    ./filedetect -n python --deny              # All files whose comm is "python" are blocked from opening
    ./filedetect -f /path/to/file.test --deny  # All files whose filename is /path/to/file.test are blocked from opening
"""

    parser = argparse.ArgumentParser(description="[*] Use KRSI to customize monitoring & blocking file operations.")

    parser.add_argument("-a", "--all", action="store_true", help="Trace all file open operations")
    parser.add_argument("-f", "--file", help="FILE to filter (e.g., /path/to/file.test)")
    parser.add_argument("-u", "--uid", help="UID to filter (e.g., 0)")
    parser.add_argument("-p", "--pid", help="PID to filter (e.g., 123456)")
    parser.add_argument("-n", "--comm", help="COMM to filter (e.g., python)")
    parser.add_argument("--deny", action="store_true", help="Deny file operations if specified")
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        print()
        print(examples)

    else:
        if args.deny: # file detector

            BPF_TEXT_KEY = 'DENY'

            mypid = str(os.getpid())
            bpf_text_LSM = bpf_text_LSM.replace('MYSELF_PID_FILTER','if (pid == %s) { return 0; }' % mypid)

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
                    return RETURN_FLAG;
                }
                """ % args.uid

                uid_text = uid_text.replace('RETURN_FLAG', '-EPERM')

                bpf_text_LSM = bpf_text_LSM.replace('UID_FILTER', uid_text)
            else:
                bpf_text_LSM = bpf_text_LSM.replace('UID_FILTER', '')

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
                    return RETURN_FLAG;
                }
                """ % args.pid

                pid_text = pid_text.replace('RETURN_FLAG', '-EPERM')

                bpf_text_LSM = bpf_text_LSM.replace('PID_FILTER',pid_text)
            else:
                bpf_text_LSM = bpf_text_LSM.replace('PID_FILTER', '')


            if args.comm:
                comm_text = """

                    char target_Comm[] = target_comm;
                    int target_Len = target_len;
                    int flag=1;

                    int comm_len = 0;
                    for(comm_len; comm_len < sizeof(data.comm); comm_len++){
                        if (data.comm[comm_len] == '\\0') break;
                    }

                    if(comm_len == target_Len){
                        int i=0;
                        for(i;i<comm_len;i++){
                            if(data.comm[i] != target_Comm[i]){
                                flag = 0;
                                break;
                            }
                        }
                    }else{
                        flag = 0;
                    }

                    if(flag){
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
                        return RETURN_FLAG;
                    }
                """

                comm_text = comm_text.replace('RETURN_FLAG', '-EPERM')

                comm_name = str(args.comm)
                comm_len = str(len(comm_name))
                comm_name = '"' + comm_name + '"'

                comm_text = comm_text.replace('target_comm',comm_name)
                comm_text = comm_text.replace('target_len',comm_len)

                bpf_text_LSM = bpf_text_LSM.replace('COMM_FILTER',comm_text)

            else:
                bpf_text_LSM = bpf_text_LSM.replace('COMM_FILTER', '')


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
                        return RETURN_FLAG;
                    }
                """

                file_text = file_text.replace('RETURN_FLAG', '-EPERM')

                file_text = file_text.replace('FILELENGTH', FILELENGTH)
                file_text = file_text.replace('DIRLENGTH', DIRLENGTH)
                file_text = file_text.replace('FILENAME', file_name)
                file_text = file_text.replace('DIRNAME', dir_path)

                bpf_text_LSM = bpf_text_LSM.replace('FILE_FILTER',file_text)

            else:
                bpf_text_LSM = bpf_text_LSM.replace('FILE_FILTER', '')


        else: # file monitor
            BPF_TEXT_KEY = 'MONITOR'
            mypid = str(os.getpid())
            bpf_text_OPENAT = bpf_text_OPENAT.replace('MYSELF_PID_FILTER','if (pid == %s) { return 0; }' % mypid)

            if args.all:
                bpf_text_OPENAT = bpf_text_OPENAT.replace('UID_FILTER', '')
                bpf_text_OPENAT = bpf_text_OPENAT.replace('PID_FILTER', '')
                bpf_text_OPENAT = bpf_text_OPENAT.replace('COMM_FILTER', '')
                bpf_text_OPENAT = bpf_text_OPENAT.replace('FILE_FILTER', 'events.perf_submit(ctx, &data, sizeof(data));')

            if args.uid:
                uid_text = """
                    if(uid == %s){
                        events.perf_submit(ctx, &data, sizeof(data));
                    }
                """ % args.uid

                bpf_text_OPENAT = bpf_text_OPENAT.replace('UID_FILTER', uid_text)
            else:
                bpf_text_OPENAT = bpf_text_OPENAT.replace('UID_FILTER', '')

            if args.pid:
                pid_text = """
                    if(pid == %s){
                        events.perf_submit(ctx, &data, sizeof(data));
                    }
                """ % args.pid

                bpf_text_OPENAT = bpf_text_OPENAT.replace('PID_FILTER', pid_text)
            else:
                bpf_text_OPENAT = bpf_text_OPENAT.replace('PID_FILTER', '')

            if args.comm:
                comm_text = """
                    int flag = 1;
                    char target_Comm[] = target_comm;
                    int target_Len = target_len;

                    int comm_len = 0;
                    for(comm_len; comm_len < sizeof(data.comm); comm_len++){
                        if (data.comm[comm_len] == '\\0') break;
                    }

                    if(comm_len == target_Len){
                        int i=0;
                        for(i;i<comm_len;i++){
                            if(data.comm[i] != target_Comm[i]){
                                flag = 0;
                                break;
                            }
                        }
                    }else{
                        flag = 0;
                    }

                    if(flag){
                        events.perf_submit(ctx, &data, sizeof(data));
                    }
                """
                comm_name = str(args.comm)
                comm_len = str(len(comm_name))
                comm_name = '"' + comm_name + '"'

                comm_text = comm_text.replace('target_comm',comm_name)
                comm_text = comm_text.replace('target_len',comm_len)

                bpf_text_OPENAT = bpf_text_OPENAT.replace('COMM_FILTER',comm_text)
            else:
                bpf_text_OPENAT = bpf_text_OPENAT.replace('COMM_FILTER','')

            if args.file:
                target_filename = str(args.file)
                target_filelen = str(len(target_filename))
                target_filename = '"' + target_filename + '"'

                file_text = """

                    int target_len = FILELENGTH;
                    char target_file[]= FILENAME;

                    int len = 0;
                    for(len; len < sizeof(data.name); len++){
                        if (data.name[len] == '\\0') break;
                    }

                    data.filelen = len;

                    if(target_len != data.filelen){
                        return 0;
                    }else{
                        int flag = 1;
                        int j = 0;
                        for(j;j<target_len;j++){
                            if(target_file[j] != data.name[j]){
                                flag = 0;
                                break;
                            }
                        }
                        if(flag){
                        events.perf_submit(ctx, &data, sizeof(data));
                        }
                    }

                """

                file_text = file_text.replace('FILELENGTH' ,target_filelen)
                file_text = file_text.replace('FILENAME' ,target_filename)

                bpf_text_OPENAT = bpf_text_OPENAT.replace('FILE_FILTER',file_text)
            else:
                bpf_text_OPENAT = bpf_text_OPENAT.replace('FILE_FILTER','')

        if BPF_TEXT_KEY == 'DENY':
            file_detecter = FileDetecter(bpf_text_LSM)
            file_detecter.run()
        else:

            file_monitor = FileMonitor(bpf_text_OPENAT)
            file_monitor.run()
