#ifndef PROC_LIST_H_
#define PROC_LIST_H_

#include "api_proxy.h"
#include "ver_control.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#include <linux/sched/task.h> // include appropriate header for newer kernels
#else
#include <linux/sched.h> // include for older kernels
#endif

#ifndef for_each_process
#define for_each_process(p) \
    for (p = &init_task; (p = next_task(p)) != &init_task; )
#endif

#ifndef next_task
#define next_task(p) \
    list_entry_rcu((p)->tasks.next, struct task_struct, tasks)
#endif

// Declaration
//////////////////////////////////////////////////////////////////////////
MY_STATIC ssize_t get_proc_pid_list(bool is_lookup_proc_file_mode, char* lpBuf, size_t buf_size, bool is_kernel_buf);

// Implementation
//////////////////////////////////////////////////////////////////////////
MY_STATIC ssize_t get_proc_pid_list(bool is_lookup_proc_file_mode, char* lpBuf, size_t buf_size, bool is_kernel_buf) {
    ssize_t count_pro_pid_list = 0;
    struct task_struct *p; // pointer to task_struct
    size_t buf_pos_proc_pid_list = 0;

    for_each_process(p) {
        int pid = p->pid;
        printk(KERN_DEBUG "for_each_process: %d\n", pid);

        count_pro_pid_list++;

        if (buf_pos_proc_pid_list >= buf_size) {
            continue;
        }

        if (is_kernel_buf) {
            memcpy((void*)((size_t)lpBuf + buf_pos_proc_pid_list), &pid, sizeof(pid));
        } else {
            if (copy_to_user((void*)((size_t)lpBuf + buf_pos_proc_pid_list), &pid, sizeof(pid))) {
                // User buffer is full, can't copy anymore
                buf_size = buf_pos_proc_pid_list;
                break;
            }
        }
        buf_pos_proc_pid_list += sizeof(pid);
    }

    return count_pro_pid_list;
}

#endif /* PROC_LIST_H_ */
