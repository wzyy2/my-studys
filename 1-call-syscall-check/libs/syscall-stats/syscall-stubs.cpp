#include "syscall-stats.h"

#include <map>
#include <mutex>

#include <dlfcn.h>
#include <grp.h>
#include <linux/bpf.h>
#include <linux/futex.h>
#include <linux/sysctl.h>
#include <mqueue.h>
#include <numaif.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/quota.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/sendfile.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <iostream>

/* not syscall */
long (*real_syscall)(long number, ...);
int (*real_puts)(const char *str);

/* posix */

/* syscall, by order */
// https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
ssize_t (*real_read)(int fd, void *buf, size_t nbytes);
ssize_t (*real_write)(int fd, const void *buf, size_t nbytes);
int (*real_open)(const char *path, int oflag, ...);
int (*real_close)(int);
int (*real_stat)(int ver, const char *pathname, struct stat *statbuf);
int (*real_fstat)(int ver, int fd, struct stat *statbuf);
int (*real_lstat)(int ver, const char *pathname, struct stat *statbuf);
int (*real_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
off_t (*real_lseek)(int fd, off_t offset, int whence);
void *(*real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int (*real_mprotect)(void *addr, size_t len, int prot);
int (*real_munmap)(void *addr, size_t length);
int (*real_brk)(void *addr);
void *(*real_sbrk)(intptr_t increment);
// rt_sigaction
// rt_sigprocmask
// rt_sigreturn
int (*real_ioctl)(int fd, unsigned long request, ...);
ssize_t (*real_pread)(int fd, void *buf, size_t count, off_t offset);
ssize_t (*real_pwrite)(int fd, const void *buf, size_t count, off_t offset);
ssize_t (*real_readv)(int fd, const struct iovec *iov, int iovcnt);
ssize_t (*real_writev)(int fd, const struct iovec *iov, int iovcnt);
int (*real_access)(const char *pathname, int mode);
int (*real_pipe)(int pipefd[2]);
int (*real_select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                   struct timeval *timeout);
int (*real_sched_yield)(void);
void *(*real_mremap)(void *old_address, size_t old_size, size_t new_size, int flags,
                     ... /* void *new_address */);
int (*real_msync)(void *addr, size_t length, int flags);
int (*real_mincore)(void *addr, size_t length, unsigned char *vec);
int (*real_madvise)(void *addr, size_t length, int advice);
int (*real_shmget)(key_t key, size_t size, int shmflg);
void *(*real_shmat)(int shmid, const void *shmaddr, int shmflg);
int (*real_shmctl)(int shmid, int cmd, struct shmid_ds *buf);
int (*real_dup)(int oldfd);
int (*real_dup2)(int oldfd, int newfd);
int (*real_pause)(void);
int (*real_nanosleep)(const struct timespec *req, struct timespec *rem);
int (*real_getitimer)(int which, struct itimerval *curr_value);
unsigned int (*real_alarm)(unsigned int seconds);
int (*real_setitimer)(int which, const struct itimerval *new_value, struct itimerval *old_value);
pid_t (*real_getpid)(void);
ssize_t (*real_sendfile)(int out_fd, int in_fd, off_t *offset, size_t count);
int (*real_socket)(int domain, int type, int protocol);
int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int (*real_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t (*real_sendto)(int sockfd, const void *buf, size_t len, int flags,
                       const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t (*real_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr,
                         socklen_t *addrlen);
ssize_t (*real_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
ssize_t (*real_recvmsg)(int sockfd, struct msghdr *msg, int flags);
int (*real_shutdown)(int sockfd, int how);
int (*real_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int (*real_listen)(int sockfd, int backlog);
int (*real_getsockname)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int (*real_getpeername)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int (*real_socketpair)(int domain, int type, int protocol, int sv[2]);
int (*real_setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int (*real_getsockopt)(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int (*real_clone)(int (*fn)(void *), void *stack, int flags, void *arg, ...);
pid_t (*real_fork)(void);
pid_t (*real_vfork)(void);
int (*real_execve)(const char *pathname, char *const argv[], char *const envp[]);
// exit
pid_t (*real_wait4)(pid_t pid, int *wstatus, int options, struct rusage *rusage);
int (*real_kill)(pid_t pid, int sig);
int (*real_uname)(struct utsname *buf);
int (*real_semget)(key_t key, int nsems, int semflg);
int (*real_semop)(int semid, struct sembuf *sops, size_t nsops);
int (*real_semctl)(int semid, int semnum, int cmd, ...);
int (*real_shmdt)(const void *shmaddr);
int (*real_msgget)(key_t key, int msgflg);
int (*real_msgsnd)(int msqid, const void *msgp, size_t msgsz, int msgflg);
ssize_t (*real_msgrcv)(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
int (*real_msgctl)(int msqid, int cmd, struct msqid_ds *buf);
int (*real_fcntl)(int fd, int cmd, ... /* arg */);
int (*real_flock)(int fd, int operation);
int (*real_fsync)(int fd);
int (*real_fdatasync)(int fd);
int (*real_truncate)(const char *path, off_t length);
int (*real_ftruncate)(int fd, off_t length);
ssize_t (*real_getdents64)(int fd, void *dirp, size_t count);
char *(*real_getcwd)(char *buf, size_t size);
int (*real_chdir)(const char *path);
int (*real_fchdir)(int fd);
int (*real_rename)(const char *oldpath, const char *newpath);
int (*real_mkdir)(const char *pathname, mode_t mode);
int (*real_rmdir)(const char *pathname);
int (*real_creat)(const char *pathname, mode_t mode);
int (*real_link)(const char *oldpath, const char *newpath);
int (*real_unlink)(const char *pathname);
int (*real_symlink)(const char *target, const char *linkpath);
ssize_t (*real_readlink)(const char *pathname, char *buf, size_t bufsiz);
int (*real_chmod)(const char *pathname, mode_t mode);
int (*real_fchown)(int fd, uid_t owner, gid_t group);
int (*real_chown)(const char *pathname, uid_t owner, gid_t group);
int (*real_lchown)(const char *pathname, uid_t owner, gid_t group);
mode_t (*real_umask)(mode_t mask);
int (*real_gettimeofday)(struct timeval *tv, struct timezone *tz);
int (*real_getrlimit)(int resource, struct rlimit *rlim);
int (*real_getrusage)(int who, struct rusage *usage);
int (*real_sysinfo)(struct sysinfo *info);
clock_t (*real_times)(struct tms *buf);
long (*real_ptrace)(enum __ptrace_request request, pid_t pid, void *addr, void *data);
uid_t (*real_getuid)(void);
void (*real_syslog)(int priority, const char *format, ...);
void (*real_vsyslog)(int priority, const char *format, va_list ap);
gid_t (*real_getgid)(void);
int (*real_setuid)(uid_t uid);
int (*real_setgid)(gid_t gid);
uid_t (*real_geteuid)(void);
gid_t (*real_getegid)(void);
int (*real_setpgid)(pid_t pid, pid_t pgid);
pid_t (*real_getpgid)(pid_t pid);
pid_t (*real_getpgrp)(void); /* POSIX.1 version */
pid_t (*real_setsid)(void);
int (*real_setreuid)(uid_t ruid, uid_t euid);
int (*real_setregid)(gid_t rgid, gid_t egid);
int (*real_getgroups)(int size, gid_t list[]);
int (*real_setgroups)(size_t size, const gid_t *list);
int (*real_setresuid)(uid_t ruid, uid_t euid, uid_t suid);
int (*real_setresgid)(gid_t rgid, gid_t egid, gid_t sgid);
int (*real_getresuid)(uid_t *ruid, uid_t *euid, uid_t *suid);
int (*real_getresgid)(gid_t *rgid, gid_t *egid, gid_t *sgid);
int (*real_setfsuid)(uid_t fsuid);
int (*real_setfsgid)(gid_t fsgid);
pid_t (*real_getsid)(pid_t pid);
// capget
// capset
// rt_sigpending
// rt_sigtimedwait
// rt_sigqueueinfo
// rt_sigsuspend
int (*real_sigaltstack)(const stack_t *ss, stack_t *old_ss);
int (*real_utime)(const char *filename, const struct utimbuf *times);
int (*real_mknod)(int vers, const char *pathname, mode_t mode, dev_t dev);
int (*real_uselib)(const char *library);
int (*real_personality)(unsigned long persona);
int (*real_ustat)(dev_t dev, struct ustat *ubuf);
int (*real_statfs)(const char *path, struct statfs *buf);
int (*real_fstatfs)(int fd, struct statfs *buf);
int (*real_sysfs)(int option, ...);
int (*real_getpriority)(int which, id_t who);
int (*real_setpriority)(int which, id_t who, int prio);
int (*real_sched_setparam)(pid_t pid, const struct sched_param *param);
int (*real_sched_getparam)(pid_t pid, struct sched_param *param);
int (*real_sched_setscheduler)(pid_t pid, int policy, const struct sched_param *param);
int (*real_sched_getscheduler)(pid_t pid);
int (*real_sched_get_priority_max)(int policy);
int (*real_sched_get_priority_min)(int policy);
int (*real_sched_rr_get_interval)(pid_t pid, struct timespec *tp);
int (*real_mlock)(const void *addr, size_t len);
int (*real_munlock)(const void *addr, size_t len);
int (*real_mlockall)(int flags);
int (*real_munlockall)(void);
int (*real_vhangup)(void);
// modify_ldt
// pivot_root
int (*real_sysctl)(struct __sysctl_args *args);
int (*real_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                  unsigned long arg5);
// arch_prctl
int (*real_adjtimex)(struct timex *buf);
int (*real_setrlimit)(int resource, const struct rlimit *rlim);
int (*real_chroot)(const char *path);
void (*real_sync)(void);
int (*real_acct)(const char *filename);
int (*real_settimeofday)(const struct timeval *tv, const struct timezone *tz);
int (*real_mount)(const char *source, const char *target, const char *filesystemtype,
                  unsigned long mountflags, const void *data);
int (*real_umount2)(const char *target, int flags);
int (*real_swapon)(const char *path, int swapflags);
int (*real_swapoff)(const char *path);
int (*real_reboot)(int cmd);
int (*real_sethostname)(const char *name, size_t len);
int (*real_setdomainname)(const char *name, size_t len);
int (*real_iopl)(int level);
int (*real_ioperm)(unsigned long from, unsigned long num, int turn_on);
// create_module
// init_module
// delete_module
// get_kernel_syms
// query_module
int (*real_quotactl)(int cmd, const char *special, int id, caddr_t addr);
// long (*real_nfsservctl)(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp);
// nfsservctl
// getpmsg
// putpmsg
// afs_syscall
// tuxcall
// security
pid_t (*real_gettid)(void);
ssize_t (*real_readahead)(int fd, off64_t offset, size_t count);
int (*real_setxattr)(const char *path, const char *name, const void *value, size_t size, int flags);
int (*real_lsetxattr)(const char *path, const char *name, const void *value, size_t size,
                      int flags);
int (*real_fsetxattr)(int fd, const char *name, const void *value, size_t size, int flags);
ssize_t (*real_getxattr)(const char *path, const char *name, void *value, size_t size);
ssize_t (*real_lgetxattr)(const char *path, const char *name, void *value, size_t size);
ssize_t (*real_fgetxattr)(int fd, const char *name, void *value, size_t size);
ssize_t (*real_listxattr)(const char *path, char *list, size_t size);
ssize_t (*real_llistxattr)(const char *path, char *list, size_t size);
ssize_t (*real_flistxattr)(int fd, char *list, size_t size);
int (*real_removexattr)(const char *path, const char *name);
int (*real_lremovexattr)(const char *path, const char *name);
int (*real_fremovexattr)(int fd, const char *name);
// tkill
time_t (*real_time)(time_t *tloc);
// futex
int (*real_sched_setaffinity)(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
int (*real_sched_getaffinity)(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
// set_thread_area
// io_setup
// io_destroy
// io_getevents
// io_submit
// io_cancel
// get_thread_area
// lookup_dcookie
int (*real_epoll_create)(int size);
int (*real_remap_file_pages)(void *addr, size_t size, int prot, size_t pgoff, int flags);
// set_tid_address
// restart_syscall
int (*real_semtimedop)(int semid, struct sembuf *sops, size_t nsops,
                       const struct timespec *timeout);
int (*real_posix_fadvise)(int fd, off_t offset, off_t len, int advice);
int (*real_timer_create)(clockid_t clockid, struct sigevent *sevp, timer_t *timerid);
int (*real_timer_settime)(timer_t timerid, int flags, const struct itimerspec *new_value,
                          struct itimerspec *old_value);
int (*real_timer_gettime)(timer_t timerid, struct itimerspec *curr_value);
int (*real_timer_getoverrun)(timer_t timerid);
int (*real_timer_delete)(timer_t timerid);
int (*real_clock_gettime)(clockid_t clockid, struct timespec *tp);
int (*real_clock_settime)(clockid_t clockid, const struct timespec *tp);
int (*real_clock_getres)(clockid_t clockid, struct timespec *res);
int (*real_clock_nanosleep)(clockid_t clockid, int flags, const struct timespec *request,
                            struct timespec *remain);
// exit_group
int (*real_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);
int (*real_epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);
int (*real_tgkill)(pid_t tgid, pid_t tid, int sig);
int (*real_utimes)(const char *filename, const struct timeval times[2]);
// vserver
// mbind
long (*real_set_mempolicy)(int mode, const unsigned long *nodemask, unsigned long maxnode);
mqd_t (*real_mq_open)(const char *name, int oflag, ...);
int (*real_mq_unlink)(const char *name);
int (*real_mq_timedsend)(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio,
                         const struct timespec *abs_timeout);
ssize_t (*real_mq_timedreceive)(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio,
                                const struct timespec *abs_timeout);
int (*real_mq_notify)(mqd_t mqdes, const struct sigevent *sevp);
// mq_getsetattr
// kexec_load
int (*real_waitid)(idtype_t idtype, id_t id, siginfo_t *infop, int options);
// add_key
// request_key
// keyctl
// ioprio_set
// ioprio_get
int (*real_inotify_init)(void);
int (*real_inotify_add_watch)(int fd, const char *pathname, uint32_t mask);
int (*real_inotify_rm_watch)(int fd, int wd);
// migrate_pages
int (*real_openat)(int dirfd, const char *pathname, int flags, ...);
int (*real_mkdirat)(int dirfd, const char *pathname, mode_t mode);
int (*real_mknodat)(int vers, int dirfd, const char *pathname, mode_t mode, dev_t dev);
int (*real_fchownat)(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
int (*real_futimesat)(int dirfd, const char *pathname, const struct timeval times[2]);
int (*real_fstatat)(int ver, int dirfd, const char *pathname, struct stat *statbuf, int flags);
int (*real_unlinkat)(int dirfd, const char *pathname, int flags);
int (*real_renameat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int (*real_linkat)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
int (*real_symlinkat)(const char *target, int newdirfd, const char *linkpath);
ssize_t (*real_readlinkat)(int dirfd, const char *pathname, char *buf, size_t bufsiz);
int (*real_fchmodat)(int dirfd, const char *pathname, mode_t mode, int flags);
int (*real_faccessat)(int dirfd, const char *pathname, int mode, int flags);
int (*real_pselect)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                    const struct timespec *timeout, const sigset_t *sigmask);
int (*real_ppoll)(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p,
                  const sigset_t *sigmask);
int (*real_unshare)(int flags);
// set_robust_list
// get_robust_list
ssize_t (*real_splice)(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out, size_t len,
                       unsigned int flags);
ssize_t (*real_tee)(int fd_in, int fd_out, size_t len, unsigned int flags);
int (*real_sync_file_range)(int fd, off64_t offset, off64_t nbytes, unsigned int flags);
ssize_t (*real_vmsplice)(int fd, const struct iovec *iov, size_t nr_segs, unsigned int flags);
// move_pages
int (*real_utimensat)(int dirfd, const char *pathname, const struct timespec times[2], int flags);
int (*real_epoll_pwait)(int epfd, struct epoll_event *events, int maxevents, int timeout,
                        const sigset_t *sigmask);
int (*real_signalfd)(int fd, const sigset_t *mask, int flags);
int (*real_timerfd_create)(int clockid, int flags);
int (*real_eventfd)(unsigned int initval, int flags);
int (*real_fallocate)(int fd, int mode, off_t offset, off_t len);
int (*real_timerfd_settime)(int fd, int flags, const struct itimerspec *new_value,
                            struct itimerspec *old_value);
int (*real_timerfd_gettime)(int fd, struct itimerspec *curr_value);
int (*real_accept4)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int (*real_epoll_create1)(int flags);
int (*real_dup3)(int oldfd, int newfd, int flags);
int (*real_pipe2)(int pipefd[2], int flags);
int (*real_inotify_init1)(int flags);
ssize_t (*real_preadv)(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t (*real_pwritev)(int fd, const struct iovec *iov, int iovcnt, off_t offset);
// rt_tgsigqueueinfo
// perf_event_open
int (*real_recvmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags,
                     struct timespec *timeout);
int (*real_fanotify_init)(unsigned int flags, unsigned int event_f_flags);
int (*real_fanotify_mark)(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd,
                          const char *pathname);
int (*real_prlimit)(pid_t pid, int resource, const struct rlimit *new_limit,
                    struct rlimit *old_limit);
int (*real_name_to_handle_at)(int dirfd, const char *pathname, struct file_handle *handle,
                              int *mount_id, int flags);
int (*real_open_by_handle_at)(int mount_fd, struct file_handle *handle, int flags);
int (*real_clock_adjtime)(clockid_t clk_id, struct timex *buf);
int (*real_syncfs)(int fd);
int (*real_sendmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);
int (*real_setns)(int fd, int nstype);
int (*real_getcpu)(unsigned int *cpu, unsigned int *node);
ssize_t (*real_process_vm_readv)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
                                 const struct iovec *remote_iov, unsigned long riovcnt,
                                 unsigned long flags);
ssize_t (*real_process_vm_writev)(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
                                  const struct iovec *remote_iov, unsigned long riovcnt,
                                  unsigned long flags);
// kcmp
// finit_module
// sched_setattr
// sched_getattr
int (*real_renameat2)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath,
                      unsigned int flags);
// seccomp
ssize_t (*real_getrandom)(void *buf, size_t buflen, unsigned int flags);
int (*real_memfd_create)(const char *name, unsigned int flags);
// kexec_file_load
int (*real_bpf)(int cmd, union bpf_attr *attr, unsigned int size);
int (*real_execveat)(int dirfd, const char *pathname, const char *const argv[],
                     const char *const envp[], int flags);
// userfaultfd
// membarrier
int (*real_mlock2)(const void *addr, size_t len, unsigned int flags);
ssize_t (*real_copy_file_range)(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out,
                                size_t len, unsigned int flags);
ssize_t (*real_preadv2)(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
ssize_t (*real_pwritev2)(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
int (*real_pkey_mprotect)(void *addr, size_t len, int prot, int pkey);
int (*real_pkey_alloc)(unsigned int flags, unsigned int access_rights);
int (*real_pkey_free)(int pkey);
int (*real_statx)(int dirfd, const char *pathname, int flags, unsigned int mask,
                  struct statx *statxbuf);

static std::mutex mtx;
const char *enum_map[SysCallIndex::MAX_NUM];

const char *SysCallIndex::name(int index) { return enum_map[index]; }

#define CHECK_DLSYM(func)                                                         \
  DEBUG_MSG(5, __func__);                                                         \
  if (func == NULL) native_init_syscalls();                                       \
  if (enum_map[SysCallIndex::func] == NULL) enum_map[SysCallIndex::func] = #func; \
  StatsThreadLocal::getInstance().DoStats(SysCallIndex::func);

static inline void *SET_DLSYM(void *handle, const char *name) {
  void *ret = dlsym(handle, name);
  if (ret == NULL) {
    DEBUG_MSG(1, "[syscall-stats] fatal when loading dlsym: " << name);
    // exit(-1);
  }
  return ret;
}

void native_init_syscalls() {
  std::lock_guard<std::mutex> lock_init(mtx);

  *(void **)(&real_puts) = SET_DLSYM(RTLD_NEXT, "puts");
  *(void **)(&real_syscall) = SET_DLSYM(RTLD_NEXT, "syscall");

  *(void **)(&real_read) = SET_DLSYM(RTLD_NEXT, "read");
  *(void **)(&real_write) = SET_DLSYM(RTLD_NEXT, "write");
  *(void **)(&real_open) = SET_DLSYM(RTLD_NEXT, "open");
  *(void **)(&real_close) = SET_DLSYM(RTLD_NEXT, "close");

  *(void **)(&real_stat) = SET_DLSYM(RTLD_NEXT, "__xstat");
  *(void **)(&real_fstat) = SET_DLSYM(RTLD_NEXT, "__fxstat");
  *(void **)(&real_lstat) = SET_DLSYM(RTLD_NEXT, "__lxstat");

  *(void **)(&real_poll) = SET_DLSYM(RTLD_NEXT, "poll");
  *(void **)(&real_lseek) = SET_DLSYM(RTLD_NEXT, "lseek");
  *(void **)(&real_mmap) = SET_DLSYM(RTLD_NEXT, "mmap");
  *(void **)(&real_mprotect) = SET_DLSYM(RTLD_NEXT, "mprotect");
  *(void **)(&real_munmap) = SET_DLSYM(RTLD_NEXT, "munmap");
  *(void **)(&real_brk) = SET_DLSYM(RTLD_NEXT, "brk");
  *(void **)(&real_sbrk) = SET_DLSYM(RTLD_NEXT, "sbrk");
  *(void **)(&real_ioctl) = SET_DLSYM(RTLD_NEXT, "ioctl");
  *(void **)(&real_pread) = SET_DLSYM(RTLD_NEXT, "pread");
  *(void **)(&real_pwrite) = SET_DLSYM(RTLD_NEXT, "pwrite");
  *(void **)(&real_readv) = SET_DLSYM(RTLD_NEXT, "readv");
  *(void **)(&real_writev) = SET_DLSYM(RTLD_NEXT, "writev");
  *(void **)(&real_access) = SET_DLSYM(RTLD_NEXT, "access");
  *(void **)(&real_pipe) = SET_DLSYM(RTLD_NEXT, "pipe");
  *(void **)(&real_select) = SET_DLSYM(RTLD_NEXT, "select");
  *(void **)(&real_sched_yield) = SET_DLSYM(RTLD_NEXT, "sched_yield");
  *(void **)(&real_mremap) = SET_DLSYM(RTLD_NEXT, "mremap");
  *(void **)(&real_msync) = SET_DLSYM(RTLD_NEXT, "msync");
  *(void **)(&real_mincore) = SET_DLSYM(RTLD_NEXT, "mincore");
  *(void **)(&real_madvise) = SET_DLSYM(RTLD_NEXT, "madvise");
  *(void **)(&real_shmget) = SET_DLSYM(RTLD_NEXT, "shmget");
  *(void **)(&real_shmat) = SET_DLSYM(RTLD_NEXT, "shmat");
  *(void **)(&real_shmctl) = SET_DLSYM(RTLD_NEXT, "shmctl");
  *(void **)(&real_dup) = SET_DLSYM(RTLD_NEXT, "dup");
  *(void **)(&real_dup2) = SET_DLSYM(RTLD_NEXT, "dup2");
  *(void **)(&real_pause) = SET_DLSYM(RTLD_NEXT, "pause");
  *(void **)(&real_nanosleep) = SET_DLSYM(RTLD_NEXT, "nanosleep");
  *(void **)(&real_getitimer) = SET_DLSYM(RTLD_NEXT, "getitimer");
  *(void **)(&real_alarm) = SET_DLSYM(RTLD_NEXT, "alarm");
  *(void **)(&real_setitimer) = SET_DLSYM(RTLD_NEXT, "setitimer");
  *(void **)(&real_getpid) = SET_DLSYM(RTLD_NEXT, "getpid");
  *(void **)(&real_sendfile) = SET_DLSYM(RTLD_NEXT, "sendfile");
  *(void **)(&real_socket) = SET_DLSYM(RTLD_NEXT, "socket");
  *(void **)(&real_connect) = SET_DLSYM(RTLD_NEXT, "connect");
  *(void **)(&real_accept) = SET_DLSYM(RTLD_NEXT, "accept");
  *(void **)(&real_sendto) = SET_DLSYM(RTLD_NEXT, "sendto");
  *(void **)(&real_recvfrom) = SET_DLSYM(RTLD_NEXT, "recvfrom");
  *(void **)(&real_sendmsg) = SET_DLSYM(RTLD_NEXT, "sendmsg");
  *(void **)(&real_recvmsg) = SET_DLSYM(RTLD_NEXT, "recvmsg");
  *(void **)(&real_shutdown) = SET_DLSYM(RTLD_NEXT, "shutdown");
  *(void **)(&real_bind) = SET_DLSYM(RTLD_NEXT, "bind");
  *(void **)(&real_listen) = SET_DLSYM(RTLD_NEXT, "listen");
  *(void **)(&real_getsockname) = SET_DLSYM(RTLD_NEXT, "getsockname");
  *(void **)(&real_getpeername) = SET_DLSYM(RTLD_NEXT, "getpeername");
  *(void **)(&real_socketpair) = SET_DLSYM(RTLD_NEXT, "socketpair");
  *(void **)(&real_socketpair) = SET_DLSYM(RTLD_NEXT, "socketpair");
  *(void **)(&real_setsockopt) = SET_DLSYM(RTLD_NEXT, "socketpair");
  *(void **)(&real_getsockopt) = SET_DLSYM(RTLD_NEXT, "getsockopt");
  *(void **)(&real_clone) = SET_DLSYM(RTLD_NEXT, "clone");
  *(void **)(&real_fork) = SET_DLSYM(RTLD_NEXT, "fork");
  *(void **)(&real_vfork) = SET_DLSYM(RTLD_NEXT, "vfork");
  *(void **)(&real_execve) = SET_DLSYM(RTLD_NEXT, "execve");
  *(void **)(&real_wait4) = SET_DLSYM(RTLD_NEXT, "wait4");
  *(void **)(&real_kill) = SET_DLSYM(RTLD_NEXT, "kill");
  *(void **)(&real_uname) = SET_DLSYM(RTLD_NEXT, "uname");
  *(void **)(&real_semget) = SET_DLSYM(RTLD_NEXT, "semget");
  *(void **)(&real_semop) = SET_DLSYM(RTLD_NEXT, "semop");
  *(void **)(&real_semctl) = SET_DLSYM(RTLD_NEXT, "semctl");
  *(void **)(&real_shmdt) = SET_DLSYM(RTLD_NEXT, "shmdt");
  *(void **)(&real_msgget) = SET_DLSYM(RTLD_NEXT, "msgget");
  *(void **)(&real_msgsnd) = SET_DLSYM(RTLD_NEXT, "msgsnd");
  *(void **)(&real_msgrcv) = SET_DLSYM(RTLD_NEXT, "msgrcv");
  *(void **)(&real_msgctl) = SET_DLSYM(RTLD_NEXT, "msgctl");
  *(void **)(&real_fcntl) = SET_DLSYM(RTLD_NEXT, "fcntl");
  *(void **)(&real_flock) = SET_DLSYM(RTLD_NEXT, "flock");
  *(void **)(&real_fsync) = SET_DLSYM(RTLD_NEXT, "fsync");
  *(void **)(&real_fdatasync) = SET_DLSYM(RTLD_NEXT, "fdatasync");
  *(void **)(&real_truncate) = SET_DLSYM(RTLD_NEXT, "truncate");
  *(void **)(&real_ftruncate) = SET_DLSYM(RTLD_NEXT, "ftruncate");
  *(void **)(&real_getdents64) = SET_DLSYM(RTLD_NEXT, "getdents64");
  *(void **)(&real_getcwd) = SET_DLSYM(RTLD_NEXT, "getcwd");
  *(void **)(&real_chdir) = SET_DLSYM(RTLD_NEXT, "chdir");
  *(void **)(&real_fchdir) = SET_DLSYM(RTLD_NEXT, "fchdir");
  *(void **)(&real_rename) = SET_DLSYM(RTLD_NEXT, "rename");
  *(void **)(&real_mkdir) = SET_DLSYM(RTLD_NEXT, "mkdir");
  *(void **)(&real_rmdir) = SET_DLSYM(RTLD_NEXT, "rmdir");
  *(void **)(&real_creat) = SET_DLSYM(RTLD_NEXT, "creat");
  *(void **)(&real_link) = SET_DLSYM(RTLD_NEXT, "link");
  *(void **)(&real_unlink) = SET_DLSYM(RTLD_NEXT, "unlink");
  *(void **)(&real_symlink) = SET_DLSYM(RTLD_NEXT, "symlink");
  *(void **)(&real_readlink) = SET_DLSYM(RTLD_NEXT, "readlink");
  *(void **)(&real_chmod) = SET_DLSYM(RTLD_NEXT, "chmod");
  *(void **)(&real_fchown) = SET_DLSYM(RTLD_NEXT, "fchown");
  *(void **)(&real_chown) = SET_DLSYM(RTLD_NEXT, "chown");
  *(void **)(&real_lchown) = SET_DLSYM(RTLD_NEXT, "lchown");
  *(void **)(&real_umask) = SET_DLSYM(RTLD_NEXT, "umask");
  *(void **)(&real_getcwd) = SET_DLSYM(RTLD_NEXT, "getcwd");
  *(void **)(&real_gettimeofday) = SET_DLSYM(RTLD_NEXT, "gettimeofday");
  *(void **)(&real_getrlimit) = SET_DLSYM(RTLD_NEXT, "getrlimit");
  *(void **)(&real_getrusage) = SET_DLSYM(RTLD_NEXT, "getrusage");
  *(void **)(&real_sysinfo) = SET_DLSYM(RTLD_NEXT, "sysinfo");
  *(void **)(&real_times) = SET_DLSYM(RTLD_NEXT, "times");
  *(void **)(&real_ptrace) = SET_DLSYM(RTLD_NEXT, "ptrace");
  *(void **)(&real_getuid) = SET_DLSYM(RTLD_NEXT, "getuid");
  *(void **)(&real_unlink) = SET_DLSYM(RTLD_NEXT, "unlink");
  *(void **)(&real_syslog) = SET_DLSYM(RTLD_NEXT, "syslog");
  *(void **)(&real_vsyslog) = SET_DLSYM(RTLD_NEXT, "vsyslog");
  *(void **)(&real_getgid) = SET_DLSYM(RTLD_NEXT, "getgid");
  *(void **)(&real_setuid) = SET_DLSYM(RTLD_NEXT, "setuid");
  *(void **)(&real_setgid) = SET_DLSYM(RTLD_NEXT, "setgid");
  *(void **)(&real_geteuid) = SET_DLSYM(RTLD_NEXT, "geteuid");
  *(void **)(&real_getegid) = SET_DLSYM(RTLD_NEXT, "getegid");
  *(void **)(&real_setpgid) = SET_DLSYM(RTLD_NEXT, "setpgid");
  *(void **)(&real_getpgid) = SET_DLSYM(RTLD_NEXT, "getpgid");
  *(void **)(&real_getpgrp) = SET_DLSYM(RTLD_NEXT, "getpgrp");
  *(void **)(&real_setsid) = SET_DLSYM(RTLD_NEXT, "setsid");
  *(void **)(&real_setreuid) = SET_DLSYM(RTLD_NEXT, "setreuid");
  *(void **)(&real_setregid) = SET_DLSYM(RTLD_NEXT, "setregid");
  *(void **)(&real_getgroups) = SET_DLSYM(RTLD_NEXT, "getgroups");
  *(void **)(&real_setgroups) = SET_DLSYM(RTLD_NEXT, "setgroups");
  *(void **)(&real_setresuid) = SET_DLSYM(RTLD_NEXT, "setresuid");
  *(void **)(&real_getresuid) = SET_DLSYM(RTLD_NEXT, "getresuid");
  *(void **)(&real_setresgid) = SET_DLSYM(RTLD_NEXT, "setresgid");
  *(void **)(&real_getresgid) = SET_DLSYM(RTLD_NEXT, "getresgid");
  *(void **)(&real_setfsuid) = SET_DLSYM(RTLD_NEXT, "setfsuid");
  *(void **)(&real_setfsgid) = SET_DLSYM(RTLD_NEXT, "setfsgid");
  *(void **)(&real_getsid) = SET_DLSYM(RTLD_NEXT, "getsid");
  *(void **)(&real_sigaltstack) = SET_DLSYM(RTLD_NEXT, "sigaltstack");
  *(void **)(&real_utime) = SET_DLSYM(RTLD_NEXT, "utime");
  *(void **)(&real_mknod) = SET_DLSYM(RTLD_NEXT, "__xmknod");
  *(void **)(&real_uselib) = SET_DLSYM(RTLD_NEXT, "uselib");
  *(void **)(&real_personality) = SET_DLSYM(RTLD_NEXT, "personality");
  *(void **)(&real_ustat) = SET_DLSYM(RTLD_NEXT, "ustat");
  *(void **)(&real_statfs) = SET_DLSYM(RTLD_NEXT, "statfs");
  *(void **)(&real_fstatfs) = SET_DLSYM(RTLD_NEXT, "fstatfs");
  // *(void **)(&real_sysfs) = SET_DLSYM(RTLD_NEXT, "sysfs");
  *(void **)(&real_setpriority) = SET_DLSYM(RTLD_NEXT, "setpriority");
  *(void **)(&real_sched_setparam) = SET_DLSYM(RTLD_NEXT, "sched_setparam");
  *(void **)(&real_getpriority) = SET_DLSYM(RTLD_NEXT, "getpriority");
  *(void **)(&real_sched_getparam) = SET_DLSYM(RTLD_NEXT, "sched_getparam");
  *(void **)(&real_sched_setscheduler) = SET_DLSYM(RTLD_NEXT, "sched_setscheduler");
  *(void **)(&real_sched_getscheduler) = SET_DLSYM(RTLD_NEXT, "sched_getscheduler");
  *(void **)(&real_sched_get_priority_max) = SET_DLSYM(RTLD_NEXT, "sched_get_priority_max");
  *(void **)(&real_sched_get_priority_min) = SET_DLSYM(RTLD_NEXT, "sched_get_priority_min");
  *(void **)(&real_sched_rr_get_interval) = SET_DLSYM(RTLD_NEXT, "sched_rr_get_interval");
  *(void **)(&real_mlock) = SET_DLSYM(RTLD_NEXT, "mlock");
  *(void **)(&real_munlock) = SET_DLSYM(RTLD_NEXT, "munlock");
  *(void **)(&real_mlockall) = SET_DLSYM(RTLD_NEXT, "mlockall");
  *(void **)(&real_munlockall) = SET_DLSYM(RTLD_NEXT, "munlockall");
  *(void **)(&real_vhangup) = SET_DLSYM(RTLD_NEXT, "vhangup");
  *(void **)(&real_sysctl) = SET_DLSYM(RTLD_NEXT, "sysctl");
  *(void **)(&real_prctl) = SET_DLSYM(RTLD_NEXT, "prctl");
  *(void **)(&real_adjtimex) = SET_DLSYM(RTLD_NEXT, "adjtimex");
  *(void **)(&real_setrlimit) = SET_DLSYM(RTLD_NEXT, "setrlimit");
  *(void **)(&real_chroot) = SET_DLSYM(RTLD_NEXT, "chroot");
  *(void **)(&real_sync) = SET_DLSYM(RTLD_NEXT, "sync");
  *(void **)(&real_acct) = SET_DLSYM(RTLD_NEXT, "acct");
  *(void **)(&real_settimeofday) = SET_DLSYM(RTLD_NEXT, "settimeofday");
  *(void **)(&real_mount) = SET_DLSYM(RTLD_NEXT, "mount");
  *(void **)(&real_umount2) = SET_DLSYM(RTLD_NEXT, "umount2");
  *(void **)(&real_swapon) = SET_DLSYM(RTLD_NEXT, "swapon");
  *(void **)(&real_swapoff) = SET_DLSYM(RTLD_NEXT, "swapoff");
  *(void **)(&real_reboot) = SET_DLSYM(RTLD_NEXT, "reboot");
  *(void **)(&real_sethostname) = SET_DLSYM(RTLD_NEXT, "sethostname");
  *(void **)(&real_setdomainname) = SET_DLSYM(RTLD_NEXT, "setdomainname");
  *(void **)(&real_iopl) = SET_DLSYM(RTLD_NEXT, "iopl");
  *(void **)(&real_ioperm) = SET_DLSYM(RTLD_NEXT, "ioperm");
  *(void **)(&real_quotactl) = SET_DLSYM(RTLD_NEXT, "quotactl");
  *(void **)(&real_gettid) = SET_DLSYM(RTLD_NEXT, "gettid");
  *(void **)(&real_readahead) = SET_DLSYM(RTLD_NEXT, "readahead");
  *(void **)(&real_setxattr) = SET_DLSYM(RTLD_NEXT, "setxattr");
  *(void **)(&real_lsetxattr) = SET_DLSYM(RTLD_NEXT, "lsetxattr");
  *(void **)(&real_fsetxattr) = SET_DLSYM(RTLD_NEXT, "fsetxattr");
  *(void **)(&real_getxattr) = SET_DLSYM(RTLD_NEXT, "getxattr");
  *(void **)(&real_lgetxattr) = SET_DLSYM(RTLD_NEXT, "lgetxattr");
  *(void **)(&real_listxattr) = SET_DLSYM(RTLD_NEXT, "listxattr");
  *(void **)(&real_fgetxattr) = SET_DLSYM(RTLD_NEXT, "fgetxattr");
  *(void **)(&real_llistxattr) = SET_DLSYM(RTLD_NEXT, "llistxattr");
  *(void **)(&real_flistxattr) = SET_DLSYM(RTLD_NEXT, "flistxattr");
  *(void **)(&real_removexattr) = SET_DLSYM(RTLD_NEXT, "removexattr");
  *(void **)(&real_lremovexattr) = SET_DLSYM(RTLD_NEXT, "lremovexattr");
  *(void **)(&real_fremovexattr) = SET_DLSYM(RTLD_NEXT, "fremovexattr");
  *(void **)(&real_time) = SET_DLSYM(RTLD_NEXT, "time");
  *(void **)(&real_sched_setaffinity) = SET_DLSYM(RTLD_NEXT, "sched_setaffinity");
  *(void **)(&real_sched_getaffinity) = SET_DLSYM(RTLD_NEXT, "sched_getaffinity");
  *(void **)(&real_epoll_create) = SET_DLSYM(RTLD_NEXT, "epoll_create");
  *(void **)(&real_remap_file_pages) = SET_DLSYM(RTLD_NEXT, "remap_file_pages");
  *(void **)(&real_semtimedop) = SET_DLSYM(RTLD_NEXT, "semtimedop");
  *(void **)(&real_posix_fadvise) = SET_DLSYM(RTLD_NEXT, "posix_fadvise");
  *(void **)(&real_timer_create) = SET_DLSYM(RTLD_NEXT, "timer_create");
  *(void **)(&real_timer_settime) = SET_DLSYM(RTLD_NEXT, "timer_settime");
  *(void **)(&real_timer_gettime) = SET_DLSYM(RTLD_NEXT, "timer_gettime");
  *(void **)(&real_timer_getoverrun) = SET_DLSYM(RTLD_NEXT, "timer_getoverrun");
  *(void **)(&real_timer_delete) = SET_DLSYM(RTLD_NEXT, "timer_delete");
  *(void **)(&real_clock_gettime) = SET_DLSYM(RTLD_NEXT, "clock_gettime");
  *(void **)(&real_clock_settime) = SET_DLSYM(RTLD_NEXT, "clock_settime");
  *(void **)(&real_clock_getres) = SET_DLSYM(RTLD_NEXT, "clock_getres");
  *(void **)(&real_clock_nanosleep) = SET_DLSYM(RTLD_NEXT, "clock_nanosleep");
  *(void **)(&real_epoll_wait) = SET_DLSYM(RTLD_NEXT, "epoll_wait");
  *(void **)(&real_epoll_ctl) = SET_DLSYM(RTLD_NEXT, "epoll_ctl");
  *(void **)(&real_tgkill) = SET_DLSYM(RTLD_NEXT, "tgkill");
  *(void **)(&real_utimes) = SET_DLSYM(RTLD_NEXT, "utimes");
  // *(void **)(&real_set_mempolicy) = SET_DLSYM(RTLD_NEXT, "set_mempolicy");
  *(void **)(&real_mq_open) = SET_DLSYM(RTLD_NEXT, "mq_open");
  *(void **)(&real_mq_unlink) = SET_DLSYM(RTLD_NEXT, "mq_unlink");
  *(void **)(&real_mq_timedsend) = SET_DLSYM(RTLD_NEXT, "mq_timedsend");
  *(void **)(&real_mq_timedreceive) = SET_DLSYM(RTLD_NEXT, "mq_timedreceive");
  *(void **)(&real_mq_notify) = SET_DLSYM(RTLD_NEXT, "mq_notify");
  *(void **)(&real_waitid) = SET_DLSYM(RTLD_NEXT, "waitid");
  *(void **)(&real_inotify_init) = SET_DLSYM(RTLD_NEXT, "inotify_init");
  *(void **)(&real_inotify_add_watch) = SET_DLSYM(RTLD_NEXT, "inotify_add_watch");
  *(void **)(&real_inotify_rm_watch) = SET_DLSYM(RTLD_NEXT, "inotify_rm_watch");
  *(void **)(&real_openat) = SET_DLSYM(RTLD_NEXT, "openat");
  *(void **)(&real_mkdirat) = SET_DLSYM(RTLD_NEXT, "mkdirat");
  *(void **)(&real_mknodat) = SET_DLSYM(RTLD_NEXT, "__xmknodat");
  *(void **)(&real_fchownat) = SET_DLSYM(RTLD_NEXT, "fchownat");
  *(void **)(&real_futimesat) = SET_DLSYM(RTLD_NEXT, "futimesat");
  *(void **)(&real_fstatat) = SET_DLSYM(RTLD_NEXT, "__fxstatat64");
  *(void **)(&real_unlinkat) = SET_DLSYM(RTLD_NEXT, "unlinkat");
  *(void **)(&real_renameat) = SET_DLSYM(RTLD_NEXT, "renameat");
  *(void **)(&real_linkat) = SET_DLSYM(RTLD_NEXT, "linkat");
  *(void **)(&real_symlinkat) = SET_DLSYM(RTLD_NEXT, "symlinkat");
  *(void **)(&real_readlinkat) = SET_DLSYM(RTLD_NEXT, "readlinkat");
  *(void **)(&real_fchmodat) = SET_DLSYM(RTLD_NEXT, "fchmodat");
  *(void **)(&real_faccessat) = SET_DLSYM(RTLD_NEXT, "faccessat");
  *(void **)(&real_pselect) = SET_DLSYM(RTLD_NEXT, "pselect");
  *(void **)(&real_ppoll) = SET_DLSYM(RTLD_NEXT, "ppoll");
  *(void **)(&real_unshare) = SET_DLSYM(RTLD_NEXT, "unshare");
  *(void **)(&real_splice) = SET_DLSYM(RTLD_NEXT, "splice");
  *(void **)(&real_tee) = SET_DLSYM(RTLD_NEXT, "tee");
  *(void **)(&real_sync_file_range) = SET_DLSYM(RTLD_NEXT, "sync_file_range");
  *(void **)(&real_vmsplice) = SET_DLSYM(RTLD_NEXT, "vmsplice");
  *(void **)(&real_utimensat) = SET_DLSYM(RTLD_NEXT, "utimensat");
  *(void **)(&real_epoll_pwait) = SET_DLSYM(RTLD_NEXT, "epoll_pwait");
  *(void **)(&real_signalfd) = SET_DLSYM(RTLD_NEXT, "signalfd");
  *(void **)(&real_timerfd_create) = SET_DLSYM(RTLD_NEXT, "timerfd_create");
  *(void **)(&real_eventfd) = SET_DLSYM(RTLD_NEXT, "eventfd");
  *(void **)(&real_fallocate) = SET_DLSYM(RTLD_NEXT, "fallocate");
  *(void **)(&real_timerfd_settime) = SET_DLSYM(RTLD_NEXT, "timerfd_settime");
  *(void **)(&real_timerfd_gettime) = SET_DLSYM(RTLD_NEXT, "timerfd_gettime");
  *(void **)(&real_accept4) = SET_DLSYM(RTLD_NEXT, "accept4");
  *(void **)(&real_epoll_create1) = SET_DLSYM(RTLD_NEXT, "epoll_create1");
  *(void **)(&real_dup3) = SET_DLSYM(RTLD_NEXT, "dup3");
  *(void **)(&real_pipe2) = SET_DLSYM(RTLD_NEXT, "pipe2");
  *(void **)(&real_inotify_init1) = SET_DLSYM(RTLD_NEXT, "inotify_init1");
  *(void **)(&real_preadv) = SET_DLSYM(RTLD_NEXT, "preadv");
  *(void **)(&real_pwritev) = SET_DLSYM(RTLD_NEXT, "pwritev");
  *(void **)(&real_recvmmsg) = SET_DLSYM(RTLD_NEXT, "pwritev");
  *(void **)(&real_fanotify_init) = SET_DLSYM(RTLD_NEXT, "fanotify_init");
  *(void **)(&real_fanotify_mark) = SET_DLSYM(RTLD_NEXT, "fanotify_mark");
  *(void **)(&real_prlimit) = SET_DLSYM(RTLD_NEXT, "prlimit");
  *(void **)(&real_name_to_handle_at) = SET_DLSYM(RTLD_NEXT, "name_to_handle_at");
  *(void **)(&real_open_by_handle_at) = SET_DLSYM(RTLD_NEXT, "open_by_handle_at");
  *(void **)(&real_clock_adjtime) = SET_DLSYM(RTLD_NEXT, "clock_adjtime");
  *(void **)(&real_syncfs) = SET_DLSYM(RTLD_NEXT, "syncfs");
  *(void **)(&real_sendmmsg) = SET_DLSYM(RTLD_NEXT, "sendmmsg");
  *(void **)(&real_setns) = SET_DLSYM(RTLD_NEXT, "setns");
  *(void **)(&real_getcpu) = SET_DLSYM(RTLD_NEXT, "getcpu");
  *(void **)(&real_process_vm_readv) = SET_DLSYM(RTLD_NEXT, "process_vm_readv");
  *(void **)(&real_process_vm_writev) = SET_DLSYM(RTLD_NEXT, "process_vm_writev");
  *(void **)(&real_renameat2) = SET_DLSYM(RTLD_NEXT, "renameat2");
  *(void **)(&real_getrandom) = SET_DLSYM(RTLD_NEXT, "getrandom");
  *(void **)(&real_memfd_create) = SET_DLSYM(RTLD_NEXT, "memfd_create");
  // *(void **)(&real_bpf) = SET_DLSYM(RTLD_NEXT, "bpf");
  // *(void **)(&real_execveat) = SET_DLSYM(RTLD_NEXT, "execveat");
  *(void **)(&real_mlock2) = SET_DLSYM(RTLD_NEXT, "mlock2");
  *(void **)(&real_copy_file_range) = SET_DLSYM(RTLD_NEXT, "copy_file_range");
  *(void **)(&real_preadv2) = SET_DLSYM(RTLD_NEXT, "preadv2");
  *(void **)(&real_pwritev2) = SET_DLSYM(RTLD_NEXT, "pwritev2");
  *(void **)(&real_pkey_mprotect) = SET_DLSYM(RTLD_NEXT, "pkey_mprotect");
  *(void **)(&real_pkey_alloc) = SET_DLSYM(RTLD_NEXT, "pkey_alloc");
  *(void **)(&real_pkey_free) = SET_DLSYM(RTLD_NEXT, "pkey_free");
  *(void **)(&real_statx) = SET_DLSYM(RTLD_NEXT, "statx");
}

int puts(const char *str) {
  CHECK_DLSYM(real_puts);
  return real_puts(str);
}

long syscall(long number, ...) {
  CHECK_DLSYM(real_syscall);

  long a1, a2, a3, a4, a5, a6;
  va_list ap;
  va_start(ap, number);
  a1 = va_arg(ap, long);
  a2 = va_arg(ap, long);
  a3 = va_arg(ap, long);
  a4 = va_arg(ap, long);
  a5 = va_arg(ap, long);
  a6 = va_arg(ap, long);
  va_end(ap);

  return real_syscall(number, a1, a2, a3, a4, a5, a6);
}

// syscall, by order,
// https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
ssize_t read(int fd, void *buf, size_t nbytes) {
  CHECK_DLSYM(real_read);
  return real_read(fd, buf, nbytes);
}

ssize_t write(int fd, const void *buf, size_t nbytes) {
  CHECK_DLSYM(real_write);
  return real_write(fd, buf, nbytes);
}

int open(const char *path, int oflag, ...) {
  CHECK_DLSYM(real_open);

  va_list ap;
  mode_t mode;

  if (oflag & O_CREAT) {
    va_start(ap, oflag);
    mode = va_arg(ap, mode_t);
    va_end(ap);
    return real_open(path, oflag, mode);
  } else
    return real_open(path, oflag);
}

int close(int fd) {
  CHECK_DLSYM(real_close);
  return real_close(fd);
}

int stat(const char *pathname, struct stat *statbuf) {
  CHECK_DLSYM(real_stat);
  return real_stat(_STAT_VER, pathname, statbuf);
}

int fstat(int fd, struct stat *statbuf) {
  CHECK_DLSYM(real_fstat);
  return real_fstat(_STAT_VER, fd, statbuf);
}

int lstat(const char *pathname, struct stat *statbuf) {
  CHECK_DLSYM(real_lstat);
  return real_lstat(_STAT_VER, pathname, statbuf);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  CHECK_DLSYM(real_poll);
  return real_poll(fds, nfds, timeout);
}

off_t lseek(int fd, off_t offset, int whence) {
  CHECK_DLSYM(real_lseek);
  return real_lseek(fd, offset, whence);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  CHECK_DLSYM(real_mmap);
  return real_mmap(addr, length, prot, flags, fd, offset);
}

int mprotect(void *addr, size_t len, int prot) {
  CHECK_DLSYM(real_mprotect);
  return real_mprotect(addr, len, prot);
}

int munmap(void *addr, size_t length) {
  CHECK_DLSYM(real_munmap);
  return real_munmap(addr, length);
}

int brk(void *addr) {
  CHECK_DLSYM(real_brk);
  return real_brk(addr);
}

void *sbrk(intptr_t increment) {
  CHECK_DLSYM(real_sbrk);
  return real_sbrk(increment);
}

int ioctl(int fd, unsigned long request, void *data) {
  CHECK_DLSYM(real_ioctl);
  return real_ioctl(fd, request, data);
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
  CHECK_DLSYM(real_pread);
  return real_pread(fd, buf, count, offset);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
  CHECK_DLSYM(real_pwrite);
  return real_pwrite(fd, buf, count, offset);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
  CHECK_DLSYM(real_readv);
  return real_readv(fd, iov, iovcnt);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
  CHECK_DLSYM(real_writev);
  return real_writev(fd, iov, iovcnt);
}

int access(const char *pathname, int mode) {
  CHECK_DLSYM(real_access);
  return real_access(pathname, mode);
}

int pipe(int pipefd[2]) {
  CHECK_DLSYM(real_pipe);
  return real_pipe(pipefd);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
  CHECK_DLSYM(real_select);
  return real_select(nfds, readfds, writefds, exceptfds, timeout);
}

int sched_yield(void) {
  CHECK_DLSYM(real_sched_yield);
  return real_sched_yield();
}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...) {
  CHECK_DLSYM(real_mremap);
  return real_mremap(old_address, old_size, new_size, flags);
}

int msync(void *addr, size_t length, int flags) {
  CHECK_DLSYM(real_msync);
  return real_msync(addr, length, flags);
}

int mincore(void *addr, size_t length, unsigned char *vec) {
  CHECK_DLSYM(real_mincore);
  return real_mincore(addr, length, vec);
}

int madvise(void *addr, size_t length, int advice) {
  CHECK_DLSYM(real_madvise);
  return real_madvise(addr, length, advice);
}

int shmget(key_t key, size_t size, int shmflg) {
  CHECK_DLSYM(real_shmget);
  return real_shmget(key, size, shmflg);
}

void *shmat(int shmid, const void *shmaddr, int shmflg) {
  CHECK_DLSYM(real_shmat);
  return real_shmat(shmid, shmaddr, shmflg);
}

int shmctl(int shmid, int cmd, struct shmid_ds *buf) {
  CHECK_DLSYM(real_shmctl);
  return real_shmctl(shmid, cmd, buf);
}

int dup(int oldfd) {
  CHECK_DLSYM(real_dup);
  return real_dup(oldfd);
}

int dup2(int oldfd, int newfd) {
  CHECK_DLSYM(real_dup2);
  return real_dup2(oldfd, newfd);
}

int pause(void) {
  CHECK_DLSYM(real_pause);
  return real_pause();
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
  CHECK_DLSYM(real_nanosleep);
  return real_nanosleep(req, rem);
}

int getitimer(int which, struct itimerval *curr_value) {
  CHECK_DLSYM(real_getitimer);
  return real_getitimer(which, curr_value);
}

unsigned int alarm(unsigned int seconds) {
  CHECK_DLSYM(real_alarm);
  return real_alarm(seconds);
}

int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) {
  CHECK_DLSYM(real_setitimer);
  return real_setitimer(which, new_value, old_value);
}

pid_t getpid(void) {
  CHECK_DLSYM(real_getpid);
  return real_getpid();
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
  CHECK_DLSYM(real_sendfile);
  return real_sendfile(out_fd, in_fd, offset, count);
}

int socket(int domain, int type, int protocol) {
  CHECK_DLSYM(real_socket);
  return real_socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  CHECK_DLSYM(real_connect);
  return real_connect(sockfd, addr, addrlen);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  CHECK_DLSYM(real_accept);
  return real_accept(sockfd, addr, addrlen);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
               socklen_t addrlen) {
  CHECK_DLSYM(real_sendto);
  return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr,
                 socklen_t *addrlen) {
  CHECK_DLSYM(real_recvfrom);
  return real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  CHECK_DLSYM(real_sendmsg);
  return real_sendmsg(sockfd, msg, flags);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
  CHECK_DLSYM(real_recvmsg);
  return real_recvmsg(sockfd, msg, flags);
}

int shutdown(int sockfd, int how) {
  CHECK_DLSYM(real_shutdown);
  return real_shutdown(sockfd, how);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  CHECK_DLSYM(real_bind);
  return real_bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
  CHECK_DLSYM(real_listen);
  return real_listen(sockfd, backlog);
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  CHECK_DLSYM(real_getsockname);
  return real_getsockname(sockfd, addr, addrlen);
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  CHECK_DLSYM(real_getpeername);
  return real_getpeername(sockfd, addr, addrlen);
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
  CHECK_DLSYM(real_socketpair);
  return real_socketpair(domain, type, protocol, sv);
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
  CHECK_DLSYM(real_setsockopt);
  return real_setsockopt(sockfd, level, optname, optval, optlen);
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
  CHECK_DLSYM(real_getsockopt);
  return real_getsockopt(sockfd, level, optname, optval, optlen);
}

int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
  CHECK_DLSYM(real_clone);

  pid_t *ptid = NULL;
  struct user_desc *tls = NULL;
  pid_t *ctid = NULL;

  va_list opt;
  va_start(opt, arg);

  if (flags & CLONE_PARENT_SETTID) {
    ptid = va_arg(opt, pid_t *);
  }
  if (flags & CLONE_SETTLS) {
    tls = va_arg(opt, struct user_desc *);
  }
  if (flags & (CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID)) {
    ctid = va_arg(opt, pid_t *);
  }

  va_end(opt);

  return real_clone(fn, stack, flags, arg, ptid, tls, ctid);
}

pid_t fork(void) {
  CHECK_DLSYM(real_fork);
  return real_fork();
}

pid_t vfork(void) {
  CHECK_DLSYM(real_vfork);
  return real_vfork();
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
  CHECK_DLSYM(real_execve);
  return real_execve(pathname, argv, envp);
}

// exit
pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage) {
  CHECK_DLSYM(real_wait4);
  return real_wait4(pid, wstatus, options, rusage);
}

int kill(pid_t pid, int sig) {
  CHECK_DLSYM(real_kill);
  return real_kill(pid, sig);
}

int uname(struct utsname *buf) {
  CHECK_DLSYM(real_uname);
  return real_uname(buf);
}

int semget(key_t key, int nsems, int semflg) {
  CHECK_DLSYM(real_semget);
  return real_semget(key, nsems, semflg);
}

int semop(int semid, struct sembuf *sops, size_t nsops) {
  CHECK_DLSYM(real_semop);
  return real_semop(semid, sops, nsops);
}

int semctl(int semid, int semnum, int cmd, ...) {
  CHECK_DLSYM(real_semctl);

  long a1;
  va_list ap;
  va_start(ap, cmd);
  a1 = va_arg(ap, long);
  va_end(ap);

  return real_semctl(semid, semnum, cmd, a1);
}

int shmdt(const void *shmaddr) {
  CHECK_DLSYM(real_shmdt);
  return real_shmdt(shmaddr);
}

int msgget(key_t key, int msgflg) {
  CHECK_DLSYM(real_msgget);
  return real_msgget(key, msgflg);
}

int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg) {
  CHECK_DLSYM(real_msgsnd);
  return real_msgsnd(msqid, msgp, msgsz, msgflg);
}

ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) {
  CHECK_DLSYM(real_msgrcv);
  return real_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
}

int msgctl(int msqid, int cmd, struct msqid_ds *buf) {
  CHECK_DLSYM(real_msgctl);
  return real_msgctl(msqid, cmd, buf);
}

int fcntl(int fd, int cmd, ...) {
  CHECK_DLSYM(real_fcntl);

  long a1;
  va_list ap;
  va_start(ap, cmd);
  a1 = va_arg(ap, long);
  va_end(ap);

  return real_fcntl(fd, cmd, a1);
}

int flock(int fd, int operation) {
  CHECK_DLSYM(real_flock);
  return real_flock(fd, operation);
}

int fsync(int fd) {
  CHECK_DLSYM(real_fsync);
  return real_fsync(fd);
}

int fdatasync(int fd) {
  CHECK_DLSYM(real_fdatasync);
  return real_fdatasync(fd);
}

int truncate(const char *path, off_t length) {
  CHECK_DLSYM(real_truncate);
  return real_truncate(path, length);
}

int ftruncate(int fd, off_t length) {
  CHECK_DLSYM(real_ftruncate);
  return real_ftruncate(fd, length);
}

ssize_t getdents64(int fd, void *dirp, size_t count) {
  CHECK_DLSYM(real_getdents64);
  return real_getdents64(fd, dirp, count);
}

char *getcwd(char *buf, size_t size) {
  CHECK_DLSYM(real_getcwd);
  return real_getcwd(buf, size);
}

int chdir(const char *path) {
  CHECK_DLSYM(real_chdir);
  return real_chdir(path);
}

int fchdir(int fd) {
  CHECK_DLSYM(real_fchdir);
  return real_fchdir(fd);
}

int rename(const char *oldpath, const char *newpath) {
  CHECK_DLSYM(real_rename);
  return real_rename(oldpath, newpath);
}

int mkdir(const char *pathname, mode_t mode) {
  CHECK_DLSYM(real_mkdir);
  return real_mkdir(pathname, mode);
}

int rmdir(const char *pathname) {
  CHECK_DLSYM(real_rmdir);
  return real_rmdir(pathname);
}

int creat(const char *pathname, mode_t mode) {
  CHECK_DLSYM(real_creat);
  return real_creat(pathname, mode);
}

int link(const char *oldpath, const char *newpath) {
  CHECK_DLSYM(real_link);
  return real_link(oldpath, newpath);
}

int unlink(const char *pathname) {
  CHECK_DLSYM(real_unlink);
  return real_unlink(pathname);
}

int symlink(const char *target, const char *linkpath) {
  CHECK_DLSYM(real_symlink);
  return real_symlink(target, linkpath);
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
  CHECK_DLSYM(real_readlink);
  return real_readlink(pathname, buf, bufsiz);
}

int chmod(const char *pathname, mode_t mode) {
  CHECK_DLSYM(real_chmod);
  return real_chmod(pathname, mode);
}

int fchown(int fd, uid_t owner, gid_t group) {
  CHECK_DLSYM(real_fchown);
  return real_fchown(fd, owner, group);
}

int chown(const char *pathname, uid_t owner, gid_t group) {
  CHECK_DLSYM(real_chown);
  return real_chown(pathname, owner, group);
}

int lchown(const char *pathname, uid_t owner, gid_t group) {
  CHECK_DLSYM(real_lchown);
  return real_lchown(pathname, owner, group);
}

mode_t umask(mode_t mask) {
  CHECK_DLSYM(real_umask);
  return real_umask(mask);
}

int gettimeofday(struct timeval *tv, struct timezone *tz) {
  CHECK_DLSYM(real_gettimeofday);
  return real_gettimeofday(tv, tz);
}

int getrlimit(int resource, struct rlimit *rlim) {
  CHECK_DLSYM(real_getrlimit);
  return real_getrlimit(resource, rlim);
}

int getrusage(int who, struct rusage *usage) {
  CHECK_DLSYM(real_getrusage);
  return real_getrusage(who, usage);
}

int sysinfo(struct sysinfo *info) {
  CHECK_DLSYM(real_sysinfo);
  return real_sysinfo(info);
}

clock_t times(struct tms *buf) {
  CHECK_DLSYM(real_times);
  return real_times(buf);
}

long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {
  CHECK_DLSYM(real_ptrace);
  return real_ptrace(request, pid, addr, data);
}

uid_t getuid(void) {
  CHECK_DLSYM(real_getuid);
  return real_getuid();
}

void syslog(int priority, const char *format, ...) {
  CHECK_DLSYM(real_vsyslog);
  va_list argp;
  va_start(argp, format);
  real_vsyslog(priority, format, argp);
  va_end(argp);
}

void vsyslog(int priority, const char *format, va_list ap) {
  CHECK_DLSYM(real_vsyslog);
  return real_vsyslog(priority, format, ap);
}

gid_t getgid(void) {
  CHECK_DLSYM(real_getgid);
  return real_getgid();
}

int setuid(uid_t uid) {
  CHECK_DLSYM(real_setuid);
  return real_setuid(uid);
}

int setgid(gid_t gid) {
  CHECK_DLSYM(real_setgid);
  return real_setgid(gid);
}

uid_t geteuid(void) {
  CHECK_DLSYM(real_geteuid);
  return real_geteuid();
}

gid_t getegid(void) {
  CHECK_DLSYM(real_getegid);
  return real_getegid();
}

int setpgid(pid_t pid, pid_t pgid) {
  CHECK_DLSYM(real_setpgid);
  return real_setpgid(pid, pgid);
}

pid_t getpgid(pid_t pid) {
  CHECK_DLSYM(real_getpgid);
  return real_getpgid(pid);
}

pid_t getpgrp(void) {
  CHECK_DLSYM(real_getpgrp);
  return real_getpgrp();
}

pid_t setsid(void) {
  CHECK_DLSYM(real_setsid);
  return real_setsid();
}

int setreuid(uid_t ruid, uid_t euid) {
  CHECK_DLSYM(real_setreuid);
  return real_setreuid(ruid, euid);
}

int setregid(gid_t rgid, gid_t egid) {
  CHECK_DLSYM(real_setregid);
  return real_setregid(rgid, egid);
}

int getgroups(int size, gid_t list[]) {
  CHECK_DLSYM(real_getgroups);
  return real_getgroups(size, list);
}

int setgroups(size_t size, const gid_t *list) {
  CHECK_DLSYM(real_setgroups);
  return real_setgroups(size, list);
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid) {
  CHECK_DLSYM(real_setresuid);
  return real_setresuid(ruid, euid, suid);
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
  CHECK_DLSYM(real_setresgid);
  return real_setresgid(rgid, egid, sgid);
}

int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
  CHECK_DLSYM(real_getresuid);
  return real_getresuid(ruid, euid, suid);
}

int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) {
  CHECK_DLSYM(real_getresgid);
  return real_getresgid(rgid, egid, sgid);
}

int setfsuid(uid_t fsuid) {
  CHECK_DLSYM(real_setfsuid);
  return real_setfsuid(fsuid);
}

int setfsgid(gid_t fsgid) {
  CHECK_DLSYM(real_setfsgid);
  return real_setfsgid(fsgid);
}

pid_t getsid(pid_t pid) {
  CHECK_DLSYM(real_getsid);
  return real_getsid(pid);
}

int sigaltstack(const stack_t *ss, stack_t *old_ss) {
  CHECK_DLSYM(real_sigaltstack);
  return real_sigaltstack(ss, old_ss);
}

int utime(const char *filename, const struct utimbuf *times) {
  CHECK_DLSYM(real_utime);
  return real_utime(filename, times);
}

int mknod(const char *pathname, mode_t mode, dev_t dev) {
  CHECK_DLSYM(real_mknod);
  return real_mknod(_MKNOD_VER, pathname, mode, dev);
}

int uselib(const char *library) {
  CHECK_DLSYM(real_uselib);
  return real_uselib(library);
}

int personality(unsigned long persona) {
  CHECK_DLSYM(real_personality);
  return real_personality(persona);
}

int ustat(dev_t dev, struct ustat *ubuf) {
  CHECK_DLSYM(real_ustat);
  return real_ustat(dev, ubuf);
}

int statfs(const char *path, struct statfs *buf) {
  CHECK_DLSYM(real_statfs);
  return real_statfs(path, buf);
}

int fstatfs(int fd, struct statfs *buf) {
  CHECK_DLSYM(real_fstatfs);
  return real_fstatfs(fd, buf);
}

int sysfs(int option, const char *fsname) {
  CHECK_DLSYM(real_sysfs);
  return real_sysfs(option, fsname);
}
int sysfs(int option, unsigned int fs_index, char *buf) {
  CHECK_DLSYM(real_sysfs);
  return real_sysfs(option, fs_index, buf);
}
int sysfs(int option) {
  CHECK_DLSYM(real_sysfs);
  return real_sysfs(option);
}

int getpriority(int which, id_t who) {
  CHECK_DLSYM(real_getpriority);
  return real_getpriority(which, who);
}

int setpriority(int which, id_t who, int prio) {
  CHECK_DLSYM(real_setpriority);
  return real_setpriority(which, who, prio);
}

int sched_setparam(pid_t pid, const struct sched_param *param) {
  CHECK_DLSYM(real_sched_setparam);
  return real_sched_setparam(pid, param);
}

int sched_getparam(pid_t pid, struct sched_param *param) {
  CHECK_DLSYM(real_sched_getparam);
  return real_sched_getparam(pid, param);
}

int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param) {
  CHECK_DLSYM(real_sched_setscheduler);
  return real_sched_setscheduler(pid, policy, param);
}

int sched_getscheduler(pid_t pid) {
  CHECK_DLSYM(real_sched_getscheduler);
  return real_sched_getscheduler(pid);
}

int sched_get_priority_max(int policy) {
  CHECK_DLSYM(real_sched_get_priority_max);
  return real_sched_get_priority_max(policy);
}

int sched_get_priority_min(int policy) {
  CHECK_DLSYM(real_sched_get_priority_min);
  return real_sched_get_priority_min(policy);
}

int sched_rr_get_interval(pid_t pid, struct timespec *tp) {
  CHECK_DLSYM(real_sched_rr_get_interval);
  return real_sched_rr_get_interval(pid, tp);
}

int mlock(const void *addr, size_t len) {
  CHECK_DLSYM(real_mlock);
  return real_mlock(addr, len);
}

int munlock(const void *addr, size_t len) {
  CHECK_DLSYM(real_munlock);
  return real_munlock(addr, len);
}

int mlockall(int flags) {
  CHECK_DLSYM(real_mlockall);
  return real_mlockall(flags);
}

int munlockall(void) {
  CHECK_DLSYM(real_munlockall);
  return real_munlockall();
}

int vhangup(void) {
  CHECK_DLSYM(real_vhangup);
  return real_vhangup();
}

int sysctl(struct __sysctl_args *args) {
  CHECK_DLSYM(real_sysctl);
  return real_sysctl(args);
}

int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
          unsigned long arg5) {
  CHECK_DLSYM(real_prctl);
  return real_prctl(option, arg2, arg3, arg4, arg5);
}

int adjtimex(struct timex *buf) {
  CHECK_DLSYM(real_adjtimex);
  return real_adjtimex(buf);
}

int setrlimit(int resource, const struct rlimit *rlim) {
  CHECK_DLSYM(real_setrlimit);
  return real_setrlimit(resource, rlim);
}

int chroot(const char *path) {
  CHECK_DLSYM(real_chroot);
  return real_chroot(path);
}

void sync(void) {
  CHECK_DLSYM(real_sync);
  return real_sync();
}

int acct(const char *filename) {
  CHECK_DLSYM(real_acct);
  return real_acct(filename);
}

int settimeofday(const struct timeval *tv, const struct timezone *tz) {
  CHECK_DLSYM(real_settimeofday);
  return real_settimeofday(tv, tz);
}

int mount(const char *source, const char *target, const char *filesystemtype,
          unsigned long mountflags, const void *data) {
  CHECK_DLSYM(real_mount);
  return real_mount(source, target, filesystemtype, mountflags, data);
}

int umount2(const char *target, int flags) {
  CHECK_DLSYM(real_umount2);
  return real_umount2(target, flags);
}

int swapon(const char *path, int swapflags) {
  CHECK_DLSYM(real_swapon);
  return real_swapon(path, swapflags);
}

int swapoff(const char *path) {
  CHECK_DLSYM(real_swapoff);
  return real_swapoff(path);
}

int reboot(int cmd) {
  CHECK_DLSYM(real_reboot);
  return real_reboot(cmd);
}

int sethostname(const char *name, size_t len) {
  CHECK_DLSYM(real_sethostname);
  return real_sethostname(name, len);
}

int setdomainname(const char *name, size_t len) {
  CHECK_DLSYM(real_setdomainname);
  return real_setdomainname(name, len);
}

int iopl(int level) {
  CHECK_DLSYM(real_iopl);
  return real_iopl(level);
}

int ioperm(unsigned long from, unsigned long num, int turn_on) {
  CHECK_DLSYM(real_ioperm);
  return real_ioperm(from, num, turn_on);
}

int quotactl(int cmd, const char *special, int id, caddr_t addr) {
  CHECK_DLSYM(real_quotactl);
  return real_quotactl(cmd, special, id, addr);
}

pid_t gettid(void) {
  CHECK_DLSYM(real_gettid);
  return real_gettid();
}

ssize_t readahead(int fd, off64_t offset, size_t count) {
  CHECK_DLSYM(real_readahead);
  return real_readahead(fd, offset, count);
}

int setxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
  CHECK_DLSYM(real_setxattr);
  return real_setxattr(path, name, value, size, flags);
}

int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
  CHECK_DLSYM(real_lsetxattr);
  return real_lsetxattr(path, name, value, size, flags);
}

int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags) {
  CHECK_DLSYM(real_fsetxattr);
  return real_fsetxattr(fd, name, value, size, flags);
}

ssize_t getxattr(const char *path, const char *name, void *value, size_t size) {
  CHECK_DLSYM(real_getxattr);
  return real_getxattr(path, name, value, size);
}

ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size) {
  CHECK_DLSYM(real_lgetxattr);
  return real_lgetxattr(path, name, value, size);
}

ssize_t fgetxattr(int fd, const char *name, void *value, size_t size) {
  CHECK_DLSYM(real_fgetxattr);
  return real_fgetxattr(fd, name, value, size);
}

ssize_t listxattr(const char *path, char *list, size_t size) {
  CHECK_DLSYM(real_listxattr);
  return real_listxattr(path, list, size);
}

ssize_t llistxattr(const char *path, char *list, size_t size) {
  CHECK_DLSYM(real_llistxattr);
  return real_llistxattr(path, list, size);
}

ssize_t flistxattr(int fd, char *list, size_t size) {
  CHECK_DLSYM(real_flistxattr);
  return real_flistxattr(fd, list, size);
}

int removexattr(const char *path, const char *name) {
  CHECK_DLSYM(real_removexattr);
  return real_removexattr(path, name);
}

int lremovexattr(const char *path, const char *name) {
  CHECK_DLSYM(real_lremovexattr);
  return real_lremovexattr(path, name);
}

int fremovexattr(int fd, const char *name) {
  CHECK_DLSYM(real_fremovexattr);
  return real_fremovexattr(fd, name);
}

// tkill
time_t time(time_t *tloc) {
  CHECK_DLSYM(real_time);
  return real_time(tloc);
}

// futex
int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
  CHECK_DLSYM(real_sched_setaffinity);
  return real_sched_setaffinity(pid, cpusetsize, mask);
}

int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
  CHECK_DLSYM(real_sched_getaffinity);
  return real_sched_getaffinity(pid, cpusetsize, mask);
}

int epoll_create(int size) {
  CHECK_DLSYM(real_epoll_create);
  return real_epoll_create(size);
}

int remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags) {
  CHECK_DLSYM(real_remap_file_pages);
  return real_remap_file_pages(addr, size, prot, pgoff, flags);
}

int semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout) {
  CHECK_DLSYM(real_semtimedop);
  return real_semtimedop(semid, sops, nsops, timeout);
}

int posix_fadvise(int fd, off_t offset, off_t len, int advice) {
  CHECK_DLSYM(real_posix_fadvise);
  return real_posix_fadvise(fd, offset, len, advice);
}

int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid) {
  CHECK_DLSYM(real_timer_create);
  return real_timer_create(clockid, sevp, timerid);
}

int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value,
                  struct itimerspec *old_value) {
  CHECK_DLSYM(real_timer_settime);
  return real_timer_settime(timerid, flags, new_value, old_value);
}

int timer_gettime(timer_t timerid, struct itimerspec *curr_value) {
  CHECK_DLSYM(real_timer_gettime);
  return real_timer_gettime(timerid, curr_value);
}

int timer_getoverrun(timer_t timerid) {
  CHECK_DLSYM(real_timer_getoverrun);
  return real_timer_getoverrun(timerid);
}

int timer_delete(timer_t timerid) {
  CHECK_DLSYM(real_timer_delete);
  return real_timer_delete(timerid);
}

int clock_gettime(clockid_t clockid, struct timespec *tp) {
  CHECK_DLSYM(real_clock_gettime);
  return real_clock_gettime(clockid, tp);
}

int clock_settime(clockid_t clockid, const struct timespec *tp) {
  CHECK_DLSYM(real_clock_settime);
  return real_clock_settime(clockid, tp);
}

int clock_getres(clockid_t clockid, struct timespec *res) {
  CHECK_DLSYM(real_clock_getres);
  return real_clock_getres(clockid, res);
}

int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *request,
                    struct timespec *remain) {
  CHECK_DLSYM(real_clock_nanosleep);
  return real_clock_nanosleep(clockid, flags, request, remain);
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
  CHECK_DLSYM(real_epoll_wait);
  return real_epoll_wait(epfd, events, maxevents, timeout);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
  CHECK_DLSYM(real_epoll_ctl);
  return real_epoll_ctl(epfd, op, fd, event);
}

int tgkill(pid_t tgid, pid_t tid, int sig) {
  CHECK_DLSYM(real_tgkill);
  return real_tgkill(tgid, tid, sig);
}

int utimes(const char *filename, const struct timeval times[2]) {
  CHECK_DLSYM(real_utimes);
  return real_utimes(filename, times);
}

// vserver
// mbind
long set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode) {
  CHECK_DLSYM(real_set_mempolicy);
  return real_set_mempolicy(mode, nodemask, maxnode);
}

mqd_t mq_open(const char *name, int oflag, ...) {
  CHECK_DLSYM(real_mq_open);

  mode_t oldmode = 0, mode = 0;
  struct mq_attr *attr = NULL;

  if (oflag & O_CREAT) {
    va_list ap;
    va_start(ap, oflag);
    mode = va_arg(ap, mode_t);
    oldmode = mode;
    attr = va_arg(ap, struct mq_attr *);
    va_end(ap);
  }

  return real_mq_open(name, oflag, mode, attr);
}

int mq_unlink(const char *name) {
  CHECK_DLSYM(real_mq_unlink);
  return real_mq_unlink(name);
}

int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio,
                 const struct timespec *abs_timeout) {
  CHECK_DLSYM(real_mq_timedsend);
  return real_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
}

ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio,
                        const struct timespec *abs_timeout) {
  CHECK_DLSYM(real_mq_timedreceive);
  return real_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
}

int mq_notify(mqd_t mqdes, const struct sigevent *sevp) {
  CHECK_DLSYM(real_mq_notify);
  return real_mq_notify(mqdes, sevp);
}

int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
  CHECK_DLSYM(real_waitid);
  return real_waitid(idtype, id, infop, options);
}

int inotify_init(void) {
  CHECK_DLSYM(real_inotify_init);
  return real_inotify_init();
}

int inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
  CHECK_DLSYM(real_inotify_add_watch);
  return real_inotify_add_watch(fd, pathname, mask);
}

int inotify_rm_watch(int fd, int wd) {
  CHECK_DLSYM(real_inotify_rm_watch);
  return real_inotify_rm_watch(fd, wd);
}

// migrate_pages
int openat(int dirfd, const char *pathname, int flags, ...) {
  CHECK_DLSYM(real_openat);
  va_list args;
  int mode;

  va_start(args, flags);
  mode = va_arg(args, int);
  va_end(args);

  return real_openat(dirfd, pathname, flags, mode);
}

int mkdirat(int dirfd, const char *pathname, mode_t mode) {
  CHECK_DLSYM(real_mkdirat);
  return real_mkdirat(dirfd, pathname, mode);
}

int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) {
  CHECK_DLSYM(real_mknodat);
  return real_mknodat(_MKNOD_VER, dirfd, pathname, mode, dev);
}

int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {
  CHECK_DLSYM(real_fchownat);
  return real_fchownat(dirfd, pathname, owner, group, flags);
}

int futimesat(int dirfd, const char *pathname, const struct timeval times[2]) {
  CHECK_DLSYM(real_futimesat);
  return real_futimesat(dirfd, pathname, times);
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
  CHECK_DLSYM(real_fstatat);
  return real_fstatat(_STAT_VER, dirfd, pathname, statbuf, flags);
}

int unlinkat(int dirfd, const char *pathname, int flags) {
  CHECK_DLSYM(real_unlinkat);
  return real_unlinkat(dirfd, pathname, flags);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
  CHECK_DLSYM(real_renameat);
  return real_renameat(olddirfd, oldpath, newdirfd, newpath);
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
  CHECK_DLSYM(real_linkat);
  return real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

int symlinkat(const char *target, int newdirfd, const char *linkpath) {
  CHECK_DLSYM(real_symlinkat);
  return real_symlinkat(target, newdirfd, linkpath);
}

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
  CHECK_DLSYM(real_readlinkat);
  return real_readlinkat(dirfd, pathname, buf, bufsiz);
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
  CHECK_DLSYM(real_fchmodat);
  return real_fchmodat(dirfd, pathname, mode, flags);
}

int faccessat(int dirfd, const char *pathname, int mode, int flags) {
  CHECK_DLSYM(real_faccessat);
  return real_faccessat(dirfd, pathname, mode, flags);
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
            const struct timespec *timeout, const sigset_t *sigmask) {
  CHECK_DLSYM(real_pselect);
  return real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask) {
  CHECK_DLSYM(real_ppoll);
  return real_ppoll(fds, nfds, tmo_p, sigmask);
}

int unshare(int flags) {
  CHECK_DLSYM(real_unshare);
  return real_unshare(flags);
}

// set_robust_list
// get_robust_list
ssize_t splice(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out, size_t len,
               unsigned int flags) {
  CHECK_DLSYM(real_splice);
  return real_splice(fd_in, off_in, fd_out, off_out, len, flags);
}

ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags) {
  CHECK_DLSYM(real_tee);
  return real_tee(fd_in, fd_out, len, flags);
}

int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags) {
  CHECK_DLSYM(real_sync_file_range);
  return real_sync_file_range(fd, offset, nbytes, flags);
}

ssize_t vmsplice(int fd, const struct iovec *iov, size_t nr_segs, unsigned int flags) {
  CHECK_DLSYM(real_vmsplice);
  return real_vmsplice(fd, iov, nr_segs, flags);
}

// move_pages
int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) {
  CHECK_DLSYM(real_utimensat);
  return real_utimensat(dirfd, pathname, times, flags);
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout,
                const sigset_t *sigmask) {
  CHECK_DLSYM(real_epoll_pwait);
  return real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

int signalfd(int fd, const sigset_t *mask, int flags) {
  CHECK_DLSYM(real_signalfd);
  return real_signalfd(fd, mask, flags);
}

int timerfd_create(int clockid, int flags) {
  CHECK_DLSYM(real_timerfd_create);
  return real_timerfd_create(clockid, flags);
}

int eventfd(unsigned int initval, int flags) {
  CHECK_DLSYM(real_eventfd);
  return real_eventfd(initval, flags);
}

int fallocate(int fd, int mode, off_t offset, off_t len) {
  CHECK_DLSYM(real_fallocate);
  return real_fallocate(fd, mode, offset, len);
}

int timerfd_settime(int fd, int flags, const struct itimerspec *new_value,
                    struct itimerspec *old_value) {
  CHECK_DLSYM(real_timerfd_settime);
  return real_timerfd_settime(fd, flags, new_value, old_value);
}

int timerfd_gettime(int fd, struct itimerspec *curr_value) {
  CHECK_DLSYM(real_timerfd_gettime);
  return real_timerfd_gettime(fd, curr_value);
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
  CHECK_DLSYM(real_accept4);
  return real_accept4(sockfd, addr, addrlen, flags);
}

int epoll_create1(int flags) {
  CHECK_DLSYM(real_epoll_create1);
  return real_epoll_create1(flags);
}

int dup3(int oldfd, int newfd, int flags) {
  CHECK_DLSYM(real_dup3);
  return real_dup3(oldfd, newfd, flags);
}

int pipe2(int pipefd[2], int flags) {
  CHECK_DLSYM(real_pipe2);
  return real_pipe2(pipefd, flags);
}

int inotify_init1(int flags) {
  CHECK_DLSYM(real_inotify_init1);
  return real_inotify_init1(flags);
}

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
  CHECK_DLSYM(real_preadv);
  return real_preadv(fd, iov, iovcnt, offset);
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
  CHECK_DLSYM(real_pwritev);
  return real_pwritev(fd, iov, iovcnt, offset);
}

// rt_tgsigqueueinfo
// perf_event_open
int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags,
             struct timespec *timeout) {
  CHECK_DLSYM(real_recvmmsg);
  return real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
}

int fanotify_init(unsigned int flags, unsigned int event_f_flags) {
  CHECK_DLSYM(real_fanotify_init);
  return real_fanotify_init(flags, event_f_flags);
}

int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd,
                  const char *pathname) {
  CHECK_DLSYM(real_fanotify_mark);
  return real_fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname);
}

int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit) {
  CHECK_DLSYM(real_prlimit);
  return real_prlimit(pid, resource, new_limit, old_limit);
}

int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id,
                      int flags) {
  CHECK_DLSYM(real_name_to_handle_at);
  return real_name_to_handle_at(dirfd, pathname, handle, mount_id, flags);
}

int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags) {
  CHECK_DLSYM(real_puts);
  return real_open_by_handle_at(mount_fd, handle, flags);
}

int clock_adjtime(clockid_t clk_id, struct timex *buf) {
  CHECK_DLSYM(real_clock_adjtime);
  return real_clock_adjtime(clk_id, buf);
}

int syncfs(int fd) {
  CHECK_DLSYM(real_syncfs);
  return real_syncfs(fd);
}

int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
  CHECK_DLSYM(real_sendmmsg);
  return real_sendmmsg(sockfd, msgvec, vlen, flags);
}

int setns(int fd, int nstype) {
  CHECK_DLSYM(real_setns);
  return real_setns(fd, nstype);
}

int getcpu(unsigned int *cpu, unsigned int *node) {
  CHECK_DLSYM(real_getcpu);
  return real_getcpu(cpu, node);
}

ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
                         const struct iovec *remote_iov, unsigned long riovcnt,
                         unsigned long flags) {
  CHECK_DLSYM(real_process_vm_readv);
  return real_process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
                          const struct iovec *remote_iov, unsigned long riovcnt,
                          unsigned long flags) {
  CHECK_DLSYM(real_process_vm_writev);
  return real_process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath,
              unsigned int flags) {
  CHECK_DLSYM(real_renameat2);
  return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
  CHECK_DLSYM(real_getrandom);
  return real_getrandom(buf, buflen, flags);
}

int memfd_create(const char *name, unsigned int flags) {
  CHECK_DLSYM(real_memfd_create);
  return real_memfd_create(name, flags);
}

int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
  CHECK_DLSYM(real_bpf);
  return real_bpf(cmd, attr, size);
}

int execveat(int dirfd, const char *pathname, const char *const argv[], const char *const envp[],
             int flags) {
  CHECK_DLSYM(real_execveat);
  return real_execveat(dirfd, pathname, argv, envp, flags);
}

int mlock2(const void *addr, size_t len, unsigned int flags) {
  CHECK_DLSYM(real_mlock2);
  return real_mlock2(addr, len, flags);
}

ssize_t copy_file_range(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out, size_t len,
                        unsigned int flags) {
  CHECK_DLSYM(real_copy_file_range);
  return real_copy_file_range(fd_in, off_in, fd_out, off_out, len, flags);
}

ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags) {
  CHECK_DLSYM(real_preadv2);
  return real_preadv2(fd, iov, iovcnt, offset, flags);
}

ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags) {
  CHECK_DLSYM(real_pwritev2);
  return real_pwritev2(fd, iov, iovcnt, offset, flags);
}

int pkey_mprotect(void *addr, size_t len, int prot, int pkey) {
  CHECK_DLSYM(real_pkey_mprotect);
  return real_pkey_mprotect(addr, len, prot, pkey);
}

int pkey_alloc(unsigned int flags, unsigned int access_rights) {
  CHECK_DLSYM(real_pkey_alloc);
  return real_pkey_alloc(flags, access_rights);
}

int pkey_free(int pkey) {
  CHECK_DLSYM(real_pkey_free);
  return real_pkey_free(pkey);
}

int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {
  CHECK_DLSYM(real_statx);
  return real_statx(dirfd, pathname, flags, mask, statxbuf);
}
