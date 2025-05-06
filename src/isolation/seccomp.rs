pub(crate) fn seccomp_init() {
	use std::convert::TryInto;

	use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

	// TODO: fine-tune accepted parameters
	// TODO: sort alphabetically
	// TODO: --file-isolation support?
	// TODO: --readonly parameter support
	let filter: BpfProgram = SeccompFilter::new(
		vec![
			(libc::SYS_accept4, vec![]),
			(libc::SYS_eventfd2, vec![]),
			(libc::SYS_clone3, vec![]),
			(libc::SYS_fcntl, vec![]),
			(libc::SYS_openat, vec![]),
			(libc::SYS_futex, vec![]),
			(libc::SYS_rt_sigprocmask, vec![]),
			(libc::SYS_futex, vec![]),
			(libc::SYS_rt_sigaction, vec![]),
			(libc::SYS_mmap, vec![]),
			(libc::SYS_munmap, vec![]),
			(libc::SYS_ioctl, vec![]),
			// todo: disable if landlock is disabled
			(libc::SYS_landlock_add_rule, vec![]),
			(libc::SYS_landlock_create_ruleset, vec![]),
			(libc::SYS_landlock_restrict_self, vec![]),
			(libc::SYS_prctl, vec![]),
			(libc::SYS_fstat, vec![]),
			(libc::SYS_write, vec![]),
			(libc::SYS_read, vec![]),
			(libc::SYS_lseek, vec![]),
			(libc::SYS_unlink, vec![]),
			(libc::SYS_close, vec![]),
			(libc::SYS_statx, vec![]),
			(libc::SYS_mprotect, vec![]),
			(libc::SYS_sched_getaffinity, vec![]),
			(libc::SYS_brk, vec![]),
			(libc::SYS_getcwd, vec![]),
			(libc::SYS_readlink, vec![]),
			(libc::SYS_prlimit64, vec![]),
			(libc::SYS_getrandom, vec![]),
			(libc::SYS_poll, vec![]),
			(libc::SYS_arch_prctl, vec![]),
			(libc::SYS_set_tid_address, vec![]),
			(libc::SYS_set_robust_list, vec![]),
			// vm shutdown
			(libc::SYS_getpid, vec![]),
			(libc::SYS_tgkill, vec![]),
			(libc::SYS_rt_sigreturn, vec![]),
			(libc::SYS_madvise, vec![]),
			(libc::SYS_exit, vec![]),
			(libc::SYS_exit_group, vec![]),
			(libc::SYS_getdents64, vec![]),
			// vm shutdown - temporary directory
			(libc::SYS_unlinkat, vec![]),
			// found using strace -tf
			(libc::SYS_rseq, vec![]),
			(libc::SYS_sigaltstack, vec![]),
		]
		.into_iter()
		.collect(),
		SeccompAction::Trap,
		SeccompAction::Allow,
		std::env::consts::ARCH.try_into().unwrap(),
	)
	.unwrap()
	.try_into()
	.unwrap();

	seccompiler::apply_filter(&filter).unwrap();
}
