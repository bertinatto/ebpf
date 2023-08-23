//go:build ignore

#include "bpf_tracing.h"
#include "common.h"

#include <asm/unistd.h>
#include <asm/unistd_64.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") index_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") syscall_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") trash_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = 256,
	.max_entries = 100,
};

#define PATH_MAX 32

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	char target_process_name[] = "blah";
	char comm[16];

	bpf_get_current_comm(&comm, sizeof(comm));
	int result = __builtin_memcmp(comm, target_process_name, sizeof(target_process_name));
	if (result != 0) {
		return 0; // Not the target process, exit
	}

	// We need to deal with the index in an atomically way.
	u32 index_key      = 0;
	u64 index_init_val = 0;
	u64 *index_ptr;
	index_ptr = bpf_map_lookup_elem(&index_map, &index_key);
	if (!index_ptr) {
		bpf_map_update_elem(&index_map, &index_key, &index_init_val, BPF_ANY);
		return 0;
	}

	// Reserves the current index value for the current syscall and atomically increments the index for the next one.
	u32 syscall_index = __sync_fetch_and_add(index_ptr, 1) % 100;

	u64 syscall_init_val = 0, *syscall_ptr;
	syscall_ptr          = bpf_map_lookup_elem(&syscall_map, &syscall_index);
	if (!syscall_ptr) {
		bpf_map_update_elem(&syscall_map, &syscall_index, &syscall_init_val, BPF_ANY);
		return 0;
	}

	unsigned long syscall_id = ctx->args[1];

	// Store syscall in our map. This effectively sends the information to user-space.
	*syscall_ptr = syscall_id;

	// Used to grab the args
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

	if (syscall_id == __NR_openat) {
		struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

		int dfd = PT_REGS_PARM1(regs);
		/* const char *pathname = (const char *)PT_REGS_PARM2(regs); */

		// Get string pointer
		/* const char *pathname_ptr; */
		u64 pathname_ptr;
		bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), &PT_REGS_PARM2(regs));

		// Read the string
		char pathname[256];
		bpf_probe_read_str(&pathname, sizeof(pathname), (void *)pathname_ptr);

		// Store in the map
		bpf_map_update_elem(&trash_map, &syscall_index, &pathname, BPF_ANY);
	}

	if (syscall_id == __NR_execve) {
		// Get string pointer
		u64 pathname_ptr;
		bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), &PT_REGS_PARM1(regs));
		/* const char fmt_str[] = "address: %d\n"; */
		/* bpf_trace_printk(fmt_str, sizeof(fmt_str), pathname_ptr); */
		/* bpf_probe_read(&pathname_ptr, sizeof(pathname_ptr), &PT_REGS_PARM2(regs)); */
		/* bpf_trace_printk(fmt_str, sizeof(fmt_str), pathname_ptr); */

		// Read the string
		char pathname[256];

		bpf_probe_read_str(&pathname, sizeof(pathname), (void *)pathname_ptr);
		/* bpf_trace_printk(fmt_str, sizeof(fmt_str), pathname); */
		bpf_map_update_elem(&trash_map, &syscall_index, &pathname, BPF_ANY);
	}

	return 0;
}
