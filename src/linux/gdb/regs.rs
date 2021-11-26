use gdbstub_arch::x86::reg::{X86SegmentRegs, X86_64CoreRegs, X87FpuInternalRegs, F80};
use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs};
use kvm_ioctls::VcpuFd;

/// [`kvm_regs`]-related [`X86_64CoreRegs`] fields.
struct Regs {
	regs: [u64; 16],
	eflags: u32,
	rip: u64,
}

impl From<kvm_regs> for Regs {
	fn from(kvm_regs: kvm_regs) -> Self {
		let regs = [
			kvm_regs.rax,
			kvm_regs.rbx,
			kvm_regs.rcx,
			kvm_regs.rdx,
			kvm_regs.rsi,
			kvm_regs.rdi,
			kvm_regs.rbp,
			kvm_regs.rsp,
			kvm_regs.r8,
			kvm_regs.r9,
			kvm_regs.r10,
			kvm_regs.r11,
			kvm_regs.r12,
			kvm_regs.r13,
			kvm_regs.r14,
			kvm_regs.r15,
		];
		// Truncating does not lose information, as upper half of RFLAGS is reserved.
		let eflags = kvm_regs.rflags as _;
		let rip = kvm_regs.rip;
		Self { regs, eflags, rip }
	}
}

impl From<Regs> for kvm_regs {
	fn from(regs: Regs) -> Self {
		kvm_regs {
			rax: regs.regs[0],
			rbx: regs.regs[1],
			rcx: regs.regs[2],
			rdx: regs.regs[3],
			rsi: regs.regs[4],
			rdi: regs.regs[5],
			rbp: regs.regs[6],
			rsp: regs.regs[7],
			r8: regs.regs[8],
			r9: regs.regs[9],
			r10: regs.regs[10],
			r11: regs.regs[11],
			r12: regs.regs[12],
			r13: regs.regs[13],
			r14: regs.regs[14],
			r15: regs.regs[15],
			rflags: regs.eflags.into(),
			rip: regs.rip,
		}
	}
}

/// [`kvm_sregs`]-related [`X86_64CoreRegs`] fields.
struct Sregs {
	segments: X86SegmentRegs,
}

impl From<kvm_sregs> for Sregs {
	fn from(kvm_sregs: kvm_sregs) -> Self {
		let segments = X86SegmentRegs {
			cs: kvm_sregs.cs.selector.into(),
			ss: kvm_sregs.ss.selector.into(),
			ds: kvm_sregs.ds.selector.into(),
			es: kvm_sregs.es.selector.into(),
			fs: kvm_sregs.fs.selector.into(),
			gs: kvm_sregs.gs.selector.into(),
		};
		Self { segments }
	}
}

impl Sregs {
	fn update(self, kvm_sregs: &mut kvm_sregs) {
		kvm_sregs.cs.selector = self.segments.cs.try_into().unwrap();
		kvm_sregs.ss.selector = self.segments.ss.try_into().unwrap();
		kvm_sregs.ds.selector = self.segments.ds.try_into().unwrap();
		kvm_sregs.es.selector = self.segments.es.try_into().unwrap();
		kvm_sregs.fs.selector = self.segments.fs.try_into().unwrap();
		kvm_sregs.gs.selector = self.segments.gs.try_into().unwrap();
	}
}

/// [`kvm_fpu`]-related [`X86_64CoreRegs`] fields.
struct Fpu {
	st: [F80; 8],
	fpu: X87FpuInternalRegs,
	xmm: [u128; 16],
	mxcsr: u32,
}

impl From<kvm_fpu> for Fpu {
	fn from(kvm_fpu: kvm_fpu) -> Self {
		// For details on `kvm_fpu` see:
		// * https://elixir.bootlin.com/linux/v5.13.1/source/arch/x86/include/uapi/asm/kvm.h#L163
		// * https://elixir.bootlin.com/linux/v5.13.1/source/arch/x86/kvm/x86.c#L10181
		// * https://elixir.bootlin.com/linux/v5.13.1/source/arch/x86/include/asm/fpu/types.h#L34

		let st = kvm_fpu.fpr.map(|fpr| fpr[..10].try_into().unwrap());

		let fpu = X87FpuInternalRegs {
			fctrl: kvm_fpu.fcw.into(),
			fstat: kvm_fpu.fsw.into(),
			ftag: kvm_fpu.ftwx.into(),
			fiseg: kvm_fpu.last_ip as _,
			fioff: (kvm_fpu.last_ip >> u32::BITS) as _,
			foseg: kvm_fpu.last_dp as _,
			fooff: (kvm_fpu.last_dp >> u32::BITS) as _,
			fop: kvm_fpu.last_opcode.into(),
		};

		let xmm = kvm_fpu.xmm.map(u128::from_ne_bytes);

		let mxcsr = kvm_fpu.mxcsr;

		Self {
			st,
			fpu,
			xmm,
			mxcsr,
		}
	}
}

impl From<Fpu> for kvm_fpu {
	fn from(fpu: Fpu) -> Self {
		let fpr = fpu
			.st
			.iter()
			.map(|fpr| [&fpr[..], &[0; 6][..]].concat().try_into().unwrap())
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		let last_ip = {
			let mut last_ip = fpu.fpu.fiseg.into();
			last_ip |= u64::from(fpu.fpu.fioff) << u32::BITS;
			last_ip
		};

		let last_dp = {
			let mut last_dp = fpu.fpu.foseg.into();
			last_dp |= u64::from(fpu.fpu.fooff) << u32::BITS;
			last_dp
		};

		let xmm = fpu
			.xmm
			.into_iter()
			.map(u128::to_ne_bytes)
			.collect::<Vec<_>>()
			.try_into()
			.unwrap();

		kvm_fpu {
			fpr,
			fcw: fpu.fpu.fctrl.try_into().unwrap(),
			fsw: fpu.fpu.fstat.try_into().unwrap(),
			ftwx: fpu.fpu.ftag.try_into().unwrap(),
			pad1: 0,
			last_opcode: fpu.fpu.fop.try_into().unwrap(),
			last_ip,
			last_dp,
			xmm,
			mxcsr: fpu.mxcsr,
			pad2: 0,
		}
	}
}

pub fn read(vcpu: &VcpuFd, regs: &mut X86_64CoreRegs) -> Result<(), kvm_ioctls::Error> {
	// TODO: Rewrite using destructuring assignment once stabilized

	let Regs {
		regs: gp_regs,
		eflags,
		rip,
	} = vcpu.get_regs()?.into();
	regs.regs = gp_regs;
	regs.eflags = eflags;
	regs.rip = rip;

	let Sregs { segments } = vcpu.get_sregs()?.into();
	regs.segments = segments;

	let Fpu {
		st,
		fpu,
		xmm,
		mxcsr,
	} = vcpu.get_fpu()?.into();
	regs.st = st;
	regs.fpu = fpu;
	regs.xmm = xmm;
	regs.mxcsr = mxcsr;

	Ok(())
}

pub fn write(regs: &X86_64CoreRegs, vcpu: &VcpuFd) -> Result<(), kvm_ioctls::Error> {
	let X86_64CoreRegs {
		regs,
		eflags,
		rip,
		segments,
		st,
		fpu,
		xmm,
		mxcsr,
	} = regs.clone();

	let kvm_regs = Regs { regs, eflags, rip }.into();
	vcpu.set_regs(&kvm_regs)?;

	let mut kvm_sregs = vcpu.get_sregs()?;
	Sregs { segments }.update(&mut kvm_sregs);
	vcpu.set_sregs(&kvm_sregs)?;

	let kvm_fpu = Fpu {
		st,
		fpu,
		xmm,
		mxcsr,
	}
	.into();
	vcpu.set_fpu(&kvm_fpu)?;

	Ok(())
}
