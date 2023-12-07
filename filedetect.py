#!/bin/python3

from bcc import BPF
import argparse
import os

class FileMonitor:
    def __init__(self, absolute_path):
        self.bpf_text = f"""
            #include <linux/fs.h>
            #include <linux/fs_struct.h>
            #include <linux/errno.h>
            #include <linux/path.h>
            #include <linux/dcache.h>

            #define MAX_ENTRIES 32

            struct data_t {{
                u32 uid;
                u32 pid;
                char comm[50];
                char name[200];
                char dir[200];
                int match;
            }};

            BPF_PERF_OUTPUT(events);

            LSM_PROBE(file_open, struct file *file) {{
                int target_file_length = FILELENGTH;
                int target_dir_length = DIRLENGTH;

                char target_filename[] = FILENAME;
                char target_dirname[] = DIRNAME;

                struct data_t data = {{}};
                struct dentry *dentry;
                struct dentry *dentry_p;

                dentry = file->f_path.dentry;
                dentry_p = dentry->d_parent;

                bpf_get_current_comm(&data.comm, sizeof(data.comm));
                u64 tid_pid = bpf_get_current_pid_tgid();
                u32 pid = tid_pid >> 32;
                u32 tid = tid_pid;
                u32 uid = bpf_get_current_uid_gid();
                data.pid = pid;
                data.uid = uid;
                data.match = 1;

                bpf_probe_read_kernel_str(&data.name, sizeof(data.name), dentry->d_name.name);
                bpf_probe_read_kernel_str(&data.dir, sizeof(data.dir), dentry_p->d_name.name);

                int len1 = 0;
                for(len1; len1 < sizeof(data.name); len1++){{
                    if (data.name[len1] == '\\0') break;
                }}

                int len2 = 0;
                for(len2; len2 < sizeof(data.dir); len2++){{
                    if (data.dir[len2] == '\\0') break;
                }}

                if(target_file_length != len1){{
                    data.match = 0;
                }}else{{
                    for(int i=0;i<len1;i++){{
                        if(target_filename[i] != data.name[i]){{
                            data.match = 0;
                            break;
                        }}
                    }}
                }}

                if(target_dir_length != len2){{
                    data.match = 0;
                }}else{{
                    for(int j=0;j<len2;j++){{
                        if(target_dirname[j] != data.dir[j]){{
                            data.match = 0;
                            break;
                        }}
                    }}
                }}

                if(data.match){{
                    events.perf_submit(ctx, &data, sizeof(data));
                    return -EPERM;
                }}
                return 0;
            }}
        """

        self.absolute_path = absolute_path

        self.dir_path, self.file_name = os.path.split(absolute_path)
        self.parent_dir, self.current_dir = os.path.split(self.dir_path)


        if not self.current_dir:
            self.current_dir = "/"

        self.bpf_text = self.bpf_text.replace('FILELENGTH', str(len(self.file_name)))
        self.bpf_text = self.bpf_text.replace('DIRLENGTH', str(len(self.current_dir)))

        self.file_name = '"' + self.file_name + '"'
        self.dir_path = '"' + self.current_dir + '"'
        self.bpf_text = self.bpf_text.replace('FILENAME', self.file_name)
        self.bpf_text = self.bpf_text.replace('DIRNAME', self.dir_path)

        self.b = BPF(text=self.bpf_text)
        self.b["events"].open_perf_buffer(self.print_event)

    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        print("[Deny!] pid:{}\tuid:{}\tcomm:{}\tfile:{}".format(event.pid, event.uid, event.comm.decode(), self.absolute_path))
        print("-------------------------------------------------------------------------------")

    def run(self):
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File monitor using eBPF")
    parser.add_argument("-f", "--file", help="Absolute path to the file to monitor", required=True)
    args = parser.parse_args()
    file_monitor = FileMonitor(args.file)

    file_monitor.run()
