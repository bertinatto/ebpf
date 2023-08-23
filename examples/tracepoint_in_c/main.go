// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/tracing/trace_pipe.
package main

import (
	"C"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)
import (
	"bytes"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 bpf tracepoint.c -- -I../headers

const MAPKEY uint32 = 0

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/tracing/events/kmem/mm_page_alloc
	// kp, err := link.Tracepoint("syscalls", "sys_enter", objs.TracepointRawSyscallsSysEnter, nil)
	// link.AttachRawTracepoint(link.RawTracepointOptions{})

	kp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.TracepointRawSyscallsSysEnter,
	})
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		for i := 0; i < 100; i++ {
			var index, syscallID uint64
			mapKey := uint32(i)
			if err := objs.SyscallMap.Lookup(mapKey, &syscallID); err != nil {
				log.Fatalf("reading syscall map: %v", err)
			}
			if err := objs.IndexMap.Lookup(uint32(0), &index); err != nil {
				log.Fatalf("reading index map: %v", err)
			}
			var arg1 []byte
			if err := objs.TrashMap.Lookup(mapKey, &arg1); err != nil {
				log.Fatalf("reading args map: %v", err)
			}

			nullIndex := bytes.IndexByte(arg1[:], 0)
			if nullIndex == -1 {
				nullIndex = len(arg1) // Set to the end of the array if not found
			}
			arg1Str := string(arg1[:nullIndex])
			// log.Printf("%d: %v -> %v\n", mapKey, value, index%10)
			// if value > 0 {
			log.Printf("%v: %v %v\n", mapKey, getSyscallName(int(syscallID)), arg1Str)
			// log.Printf("%v %v\n", getSyscallName(int(value)), string(v[:nullIndex]))
			// }
		}
		log.Println("--------------------------------------------------------------")
	}
}

func getSyscallName(id int) string {
	name, found := syscallMap[id]
	if !found {
		return ""
	}
	return name
}

var syscallMap = map[int]string{
	257: "openat",
	156: "_sysctl",
	43:  "accept",
	288: "accept4",
	21:  "access",
	163: "acct",
	248: "add_key",
	159: "adjtimex",
	183: "afs_syscall",
	37:  "alarm",
	158: "arch_prctl",
	49:  "bind",
	321: "bpf",
	12:  "brk",
	125: "capget",
	126: "capset",
	80:  "chdir",
	90:  "chmod",
	92:  "chown",
	161: "chroot",
	305: "clock_adjtime",
	229: "clock_getres",
	228: "clock_gettime",
	230: "clock_nanosleep",
	227: "clock_settime",
	56:  "clone",
	3:   "close",
	42:  "connect",
	326: "copy_file_range",
	85:  "creat",
	174: "create_module",
	176: "delete_module",
	32:  "dup",
	33:  "dup2",
	292: "dup3",
	213: "epoll_create",
	291: "epoll_create1",
	233: "epoll_ctl",
	214: "epoll_ctl_old",
	281: "epoll_pwait",
	232: "epoll_wait",
	215: "epoll_wait_old",
	284: "eventfd",
	290: "eventfd2",
	59:  "execve",
	322: "execveat",
	60:  "exit",
	231: "exit_group",
	269: "faccessat",
	221: "fadvise64",
	285: "fallocate",
	300: "fanotify_init",
	301: "fanotify_mark",
	81:  "fchdir",
	91:  "fchmod",
	268: "fchmodat",
	93:  "fchown",
	260: "fchownat",
	72:  "fcntl",
	75:  "fdatasync",
	193: "fgetxattr",
	313: "finit_module",
	196: "flistxattr",
	73:  "flock",
	57:  "fork",
	199: "fremovexattr",
	190: "fsetxattr",
	5:   "fstat",
	138: "fstatfs",
	74:  "fsync",
	77:  "ftruncate",
	202: "futex",
	261: "futimesat",
	177: "get_kernel_syms",
	239: "get_mempolicy",
	274: "get_robust_list",
	211: "get_thread_area",
	309: "getcpu",
	79:  "getcwd",
	78:  "getdents",
	217: "getdents64",
	108: "getegid",
	107: "geteuid",
	104: "getgid",
	115: "getgroups",
	36:  "getitimer",
	52:  "getpeername",
	121: "getpgid",
	111: "getpgrp",
	39:  "getpid",
	181: "getpmsg",
	110: "getppid",
	140: "getpriority",
	318: "getrandom",
	120: "getresgid",
	118: "getresuid",
	97:  "getrlimit",
	98:  "getrusage",
	124: "getsid",
	51:  "getsockname",
	55:  "getsockopt",
	186: "gettid",
	96:  "gettimeofday",
	102: "getuid",
	191: "getxattr",
	175: "init_module",
	254: "inotify_add_watch",
	253: "inotify_init",
	294: "inotify_init1",
	255: "inotify_rm_watch",
	210: "io_cancel",
	207: "io_destroy",
	208: "io_getevents",
	206: "io_setup",
	209: "io_submit",
	16:  "ioctl",
	173: "ioperm",
	172: "iopl",
	252: "ioprio_get",
	251: "ioprio_set",
	312: "kcmp",
	320: "kexec_file_load",
	246: "kexec_load",
	250: "keyctl",
	62:  "kill",
	94:  "lchown",
	192: "lgetxattr",
	86:  "link",
	265: "linkat",
	50:  "listen",
	194: "listxattr",
	195: "llistxattr",
	212: "lookup_dcookie",
	198: "lremovexattr",
	8:   "lseek",
	189: "lsetxattr",
	6:   "lstat",
	28:  "madvise",
	237: "mbind",
	324: "membarrier",
	319: "memfd_create",
	256: "migrate_pages",
	27:  "mincore",
	83:  "mkdir",
	258: "mkdirat",
	133: "mknod",
	259: "mknodat",
	149: "mlock",
	325: "mlock2",
	151: "mlockall",
	9:   "mmap",
	154: "modify_ldt",
	165: "mount",
	279: "move_pages",
	10:  "mprotect",
	245: "mq_getsetattr",
	244: "mq_notify",
	240: "mq_open",
	243: "mq_timedreceive",
	242: "mq_timedsend",
	241: "mq_unlink",
	25:  "mremap",
	71:  "msgctl",
	68:  "msgget",
	70:  "msgrcv",
	69:  "msgsnd",
	26:  "msync",
	150: "munlock",
	152: "munlockall",
	11:  "munmap",
	303: "name_to_handle_at",
	35:  "nanosleep",
	262: "newfstatat",
	180: "nfsservctl",
	84:  "rmdir",
	13:  "rt_sigaction",
	127: "rt_sigpending",
	14:  "rt_sigprocmask",
	129: "rt_sigqueueinfo",
	15:  "rt_sigreturn",
	130: "rt_sigsuspend",
	128: "rt_sigtimedwait",
	297: "rt_tgsigqueueinfo",
	146: "sched_get_priority_max",
	147: "sched_get_priority_min",
	204: "sched_getaffinity",
	315: "sched_getattr",
	143: "sched_getparam",
	145: "sched_getscheduler",
	148: "sched_rr_get_interval",
	203: "sched_setaffinity",
	314: "sched_setattr",
	142: "sched_setparam",
	144: "sched_setscheduler",
	24:  "sched_yield",
	317: "seccomp",
	185: "security",
	23:  "select",
	66:  "semctl",
	64:  "semget",
	65:  "semop",
	220: "semtimedop",
	40:  "sendfile",
	307: "sendmmsg",
	46:  "sendmsg",
	44:  "sendto",
	238: "set_mempolicy",
	273: "set_robust_list",
	205: "set_thread_area",
	218: "set_tid_address",
	171: "setdomainname",
	123: "setfsgid",
	122: "setfsuid",
	106: "setgid",
	116: "setgroups",
	170: "sethostname",
	38:  "setitimer",
	308: "setns",
	109: "setpgid",
	141: "setpriority",
	114: "setregid",
	119: "setresgid",
	117: "setresuid",
	113: "setreuid",
	160: "setrlimit",
	112: "setsid",
	54:  "setsockopt",
	164: "settimeofday",
	105: "setuid",
	188: "setxattr",
	30:  "shmat",
	31:  "shmctl",
	67:  "shmdt",
	29:  "shmget",
	48:  "shutdown",
	131: "sigaltstack",
	282: "signalfd",
	289: "signalfd4",
	41:  "socket",
	53:  "socketpair",
	275: "splice",
	4:   "stat",
	137: "statfs",
	332: "statx",
	168: "swapoff",
	167: "swapon",
	88:  "symlink",
	266: "symlinkat",
	162: "sync",
	277: "sync_file_range",
	306: "syncfs",
	139: "sysfs",
	99:  "sysinfo",
	103: "syslog",
	276: "tee",
	234: "tgkill",
	201: "time",
	222: "timer_create",
	226: "timer_delete",
	225: "timer_getoverrun",
	224: "timer_gettime",
	223: "timer_settime",
	283: "timerfd_create",
	287: "timerfd_gettime",
	286: "timerfd_settime",
	100: "times",
	200: "tkill",
	76:  "truncate",
	184: "tuxcall",
	95:  "umask",
	166: "umount2",
	63:  "uname",
	87:  "unlink",
	263: "unlinkat",
	272: "unshare",
	134: "uselib",
	323: "userfaultfd",
	136: "ustat",
	132: "utime",
	280: "utimensat",
	235: "utimes",
	58:  "vfork",
	153: "vhangup",
	278: "vmsplice",
	236: "vserver",
	61:  "wait4",
	247: "waitid",
	1:   "write",
	20:  "writev",
}
