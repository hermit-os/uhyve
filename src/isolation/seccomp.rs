use kvm_bindings::{KVM_CAP_ENABLE_CAP, KVM_CREATE_DEVICE_TEST};
use seccompiler::{
	SeccompAction, SeccompCmpArgLen, SeccompCmpOp::Eq, SeccompCondition, SeccompRule,
};
pub(crate) fn seccomp_init() {
	use std::convert::TryInto;

	use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

	// TODO: fine-tune accepted parameters
	// TODO: sort alphabetically
	// TODO: --file-isolation support?
	// TODO: --readonly parameter support

	fn seccomp_vm_rules() -> Vec<(i64, Vec<SeccompRule>)> {
		vec![
			(libc::SYS_eventfd2, vec![]),
			(libc::SYS_clone3, vec![]),
			(libc::SYS_futex, vec![]),
			(libc::SYS_rt_sigaction, vec![]),
			(libc::SYS_rt_sigprocmask, vec![]),
			(libc::SYS_poll, vec![]),
			(libc::SYS_set_tid_address, vec![]),
			(libc::SYS_set_robust_list, vec![]),
			(libc::SYS_mprotect, vec![]),
			(libc::SYS_sched_getaffinity, vec![]),
			(libc::SYS_brk, vec![]),
			(libc::SYS_prlimit64, vec![]),
			(libc::SYS_getrandom, vec![]),
		]
	}

	fn seccomp_landlock_rules() -> Vec<(i64, Vec<SeccompRule>)> {
		vec![
			(libc::SYS_landlock_add_rule, vec![]),
			(libc::SYS_landlock_create_ruleset, vec![]),
			(libc::SYS_landlock_restrict_self, vec![]),
			(libc::SYS_prctl, vec![]),
			(libc::SYS_arch_prctl, vec![]),
		]
	}

	fn seccomp_sighandler_rules() -> Vec<(i64, Vec<SeccompRule>)> {
		vec![
			(libc::SYS_futex, vec![]),
			(libc::SYS_mmap, vec![]),
			(libc::SYS_munmap, vec![]),
			// TODO: limit ioctl
			(libc::SYS_ioctl, vec![]),
		]
	}

	fn seccomp_fs_rules() -> Vec<(i64, Vec<SeccompRule>)> {
		vec![
			// Filesystem operations which are also included in hypercalls
			(libc::SYS_fstat, vec![]),
			(libc::SYS_write, vec![]),
			(libc::SYS_read, vec![]),
			(libc::SYS_lseek, vec![]),
			(libc::SYS_unlink, vec![]),
			(libc::SYS_close, vec![]),
			(libc::SYS_statx, vec![]),
			// Miscellaneous filesystem operations
			(libc::SYS_readlink, vec![]),
			(libc::SYS_getcwd, vec![]),
			(libc::SYS_fcntl, vec![]),
			(libc::SYS_openat, vec![]),
		]
	}

	fn seccomp_vcpu_rules() -> Vec<(i64, Vec<SeccompRule>)> {
		vec![
			(libc::SYS_getpid, vec![]),
			(libc::SYS_tgkill, vec![]),
			(libc::SYS_rt_sigreturn, vec![]),
			(libc::SYS_madvise, vec![]),
			(libc::SYS_exit, vec![]),
			(libc::SYS_exit_group, vec![]),
			(libc::SYS_getdents64, vec![]),
			(libc::SYS_unlinkat, vec![]), // Temporary directory
		]
	}

	fn seccomp_child_process_rules() -> Vec<(i64, Vec<SeccompRule>)> {
		vec![(libc::SYS_rseq, vec![]), (libc::SYS_sigaltstack, vec![])]
	}

	let rules = [
		seccomp_vm_rules(),
		seccomp_landlock_rules(),
		seccomp_sighandler_rules(),
		seccomp_fs_rules(),
		seccomp_vcpu_rules(),
		seccomp_child_process_rules(),
	]
	.concat();

	let filter: BpfProgram = SeccompFilter::new(
		rules.into_iter().collect(),
		SeccompAction::Trap,
		SeccompAction::Allow,
		std::env::consts::ARCH.try_into().unwrap(),
	)
	.unwrap()
	.try_into()
	.unwrap();

	seccompiler::apply_filter(&filter).unwrap();
}
