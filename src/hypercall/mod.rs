use std::io;

use uhyve_interface::{GuestPhysAddr, v1, v2};

use crate::{
	HypervisorResult,
	mem::MmapMemory,
	mem_layout::MemoryLayout,
	net::NetworkBackend,
	vcpu::VcpuStopReason,
	vm::{KernelInfo, VmPeripherals},
};

mod by_fd;
mod by_path;
mod cmdval_copy;
mod fstat;
mod getdents;

use by_fd::{close, lseek, lseek_v1, read, read_v1, write, write_v1};
use by_path::{mkdir, open, unlink};
use fstat::{fstat, stat};
use getdents::getdents;

/// `addr` is the address of the hypercall parameter in the guest's memory space. `data` is the
/// parameter that was sent to that address by the guest.
///
/// # Safety
///
/// - The return value is only valid, as long as the guest is halted.
/// - This fn must not be called multiple times on the same data, to avoid creating mutable aliasing.
pub unsafe fn address_to_hypercall_v1(
	mem: &MmapMemory,
	addr: u16,
	data: GuestPhysAddr,
) -> Option<v1::Hypercall<'_>> {
	use v1::{Hypercall, HypercallAddress};
	// Using a macro here is necessary because it:
	// - is used to reduce repetition,
	// - has to capture values from the environment (mem, data),
	// - has to be generic over its return type.
	//
	// So neither functions nor closures can serve this purpose alone.
	macro_rules! get_data {
		() => {{ unsafe { mem.get_ref_mut(data).unwrap() } }};
	}

	Some(match HypercallAddress::try_from(addr).ok()? {
		HypercallAddress::FileClose => Hypercall::FileClose(get_data!()),
		HypercallAddress::FileLseek => Hypercall::FileLseek(get_data!()),
		HypercallAddress::FileOpen => Hypercall::FileOpen(get_data!()),
		HypercallAddress::FileRead => Hypercall::FileRead(get_data!()),
		HypercallAddress::FileWrite => Hypercall::FileWrite(get_data!()),
		HypercallAddress::FileUnlink => Hypercall::FileUnlink(get_data!()),
		HypercallAddress::Exit => Hypercall::Exit(get_data!()),
		HypercallAddress::Cmdsize => Hypercall::Cmdsize(get_data!()),
		HypercallAddress::Cmdval => Hypercall::Cmdval(get_data!()),
		HypercallAddress::Uart => Hypercall::SerialWriteByte(data.as_u64() as u8),
		HypercallAddress::SerialBufferWrite => Hypercall::SerialWriteBuffer(get_data!()),
		_ => return None,
	})
}

/// `addr` is the address of the hypercall parameter in the guest's memory space. `data` is the
/// parameter that was sent to that address by the guest.
///
/// # Safety
///
/// - The return value is only valid, as long as the guest is halted.
/// - This fn must not be called multiple times on the same data, to avoid creating mutable aliasing.
pub unsafe fn address_to_hypercall_v2(
	mem: &MmapMemory,
	addr: u64,
	data: GuestPhysAddr,
) -> Option<v2::Hypercall<'_>> {
	use v2::{Hypercall, HypercallAddress};
	// Using a macro here is necessary because it:
	// - is used to reduce repetition,
	// - has to capture values from the environment (mem, data),
	// - has to be generic over its return type.
	//
	// So neither functions nor closures can serve this purpose alone.
	macro_rules! get_data {
		() => {{ unsafe { mem.get_ref_mut(data).unwrap() } }};
	}

	Some(match HypercallAddress::try_from(addr).ok()? {
		HypercallAddress::FileClose => Hypercall::FileClose(get_data!()),
		HypercallAddress::FileLseek => Hypercall::FileLseek(get_data!()),
		HypercallAddress::FileOpen => Hypercall::FileOpen(get_data!()),
		HypercallAddress::FileRead => Hypercall::FileRead(get_data!()),
		HypercallAddress::FileWrite => Hypercall::FileWrite(get_data!()),
		HypercallAddress::FileUnlink => Hypercall::FileUnlink(get_data!()),
		HypercallAddress::Exit => Hypercall::Exit(data.as_u64() as i32),
		HypercallAddress::SerialReadBuffer => Hypercall::SerialReadBuffer(get_data!()),
		HypercallAddress::SerialWriteBuffer => Hypercall::SerialWriteBuffer(get_data!()),
		HypercallAddress::SerialWriteByte => Hypercall::SerialWriteByte(data.as_u64() as u8),
		HypercallAddress::Getdents => Hypercall::Getdents(get_data!()),
		HypercallAddress::FileStat => Hypercall::FileStat(get_data!()),
		HypercallAddress::FileFstat => Hypercall::FileFstat(get_data!()),
		HypercallAddress::Mkdir => Hypercall::Mkdir(get_data!()),
		_ => return None,
	})
}

/// Given the `peripherals` of the vCPUs, handles an [`v2::Hypercall`], usually performing I/O.
///
/// # Panics
///
/// When a hypercall returns an error, or the hypercall is invalid, this function might panic
/// (particularly on failing write calls, due to historical legacy).
pub fn handle_hypercall_v2<N: NetworkBackend>(
	peripherals: &VmPeripherals<N>,
	hypercall: v2::Hypercall<'_>,
) -> Option<VcpuStopReason> {
	#[cfg(debug_assertions)]
	trace!("hypercall v2: {:?}", hypercall);

	let file_mapping = || peripherals.file_mapping.lock().unwrap();
	match hypercall {
		v2::Hypercall::Exit(sysexit) => {
			return Some(VcpuStopReason::Exit(sysexit));
		}
		v2::Hypercall::FileClose(sysclose) => close(sysclose, &mut file_mapping()),
		v2::Hypercall::FileLseek(syslseek) => lseek(syslseek, &mut file_mapping()),
		v2::Hypercall::FileOpen(sysopen) => open(&peripherals.mem, sysopen, &mut file_mapping()),
		v2::Hypercall::FileRead(sysread) => read(&peripherals.mem, sysread, &mut file_mapping()),
		v2::Hypercall::FileWrite(syswrite) => {
			write(peripherals, syswrite, &mut file_mapping()).unwrap();
		}
		v2::Hypercall::FileUnlink(sysunlink) => {
			unlink(&peripherals.mem, sysunlink, &mut file_mapping())
		}
		v2::Hypercall::Getdents(sysgetdents) => {
			getdents(&peripherals.mem, sysgetdents, &mut file_mapping())
		}
		v2::Hypercall::FileStat(sysstat) => stat(&peripherals.mem, sysstat, &file_mapping()),
		v2::Hypercall::FileFstat(sysfstat) => fstat(&peripherals.mem, sysfstat, &file_mapping()),
		v2::Hypercall::Mkdir(sysmkdir) => mkdir(&peripherals.mem, sysmkdir, &mut file_mapping()),
		v2::Hypercall::SerialWriteByte(buf) => peripherals
			.serial
			.output(&[buf])
			.unwrap_or_else(|e| error!("{e:?}")),
		v2::Hypercall::SerialWriteBuffer(sysserialwrite) => {
			// SAFETY: as this buffer is only read and not used afterwards, we don't create multiple aliasing
			let buf = unsafe {
				peripherals
					.mem
					.slice_at(sysserialwrite.buf, sysserialwrite.len as usize)
					.unwrap_or_else(|e| {
						panic!(
							"Error {e}: Systemcall parameters for SerialWriteBuffer are invalid: {sysserialwrite:?}"
						)
					})
			};

			peripherals
				.serial
				.output(buf)
				.unwrap_or_else(|e| error!("{e:?}"))
		}
		_ => panic!("Got unknown hypercall {hypercall:?}"),
	}

	None
}

/// Given the `peripherals` of the vCPUs, handles an [`v1::Hypercall`], usually performing I/O.
///
/// # Panics
///
/// When a hypercall returns an error, or the hypercall is invalid, this function might panic
/// (particularly on failing write calls).
pub fn handle_hypercall_v1<N: NetworkBackend, L: MemoryLayout>(
	peripherals: &VmPeripherals<N>,
	kernel_info: &KernelInfo<L>,
	root_pt: impl FnOnce() -> HypervisorResult<GuestPhysAddr>,
	hypercall: v1::Hypercall<'_>,
) -> Option<HypervisorResult<VcpuStopReason>> {
	#[cfg(debug_assertions)]
	trace!("hypercall v1: {:?}", hypercall);

	let file_mapping = || peripherals.file_mapping.lock().unwrap();
	match hypercall {
		v1::Hypercall::Cmdsize(syssize) => {
			syssize.update(&kernel_info.path, &kernel_info.params.kernel_args)
		}
		v1::Hypercall::Cmdval(syscmdval) => {
			cmdval_copy::copy_argv(
				kernel_info.path.as_os_str(),
				&kernel_info.params.kernel_args,
				syscmdval,
				&peripherals.mem,
			);
			cmdval_copy::copy_env(&kernel_info.params.env, syscmdval, &peripherals.mem);
		}
		v1::Hypercall::Exit(sysexit) => {
			return Some(Ok(VcpuStopReason::Exit(sysexit.arg)));
		}
		v1::Hypercall::FileClose(sysclose) => close(sysclose, &mut file_mapping()),
		v1::Hypercall::FileLseek(syslseek) => lseek_v1(syslseek, &mut file_mapping()),
		v1::Hypercall::FileOpen(sysopen) => open(&peripherals.mem, sysopen, &mut file_mapping()),
		v1::Hypercall::FileRead(sysread) => read_v1(
			&peripherals.mem,
			sysread,
			match root_pt() {
				Ok(root_pt) => root_pt,
				Err(e) => return Some(Err(e)),
			},
			&mut file_mapping(),
		),
		v1::Hypercall::FileWrite(syswrite) => write_v1(
			peripherals,
			syswrite,
			match root_pt() {
				Ok(root_pt) => root_pt,
				Err(e) => return Some(Err(e)),
			},
			&mut file_mapping(),
		)
		.unwrap(),
		v1::Hypercall::FileUnlink(sysunlink) => {
			unlink(&peripherals.mem, sysunlink, &mut file_mapping())
		}
		v1::Hypercall::SerialWriteByte(buf) => peripherals
			.serial
			.output(&[buf])
			.unwrap_or_else(|e| error!("{e:?}")),
		v1::Hypercall::SerialWriteBuffer(sysserialwrite) => {
			// safety: as this buffer is only read and not used afterwards, we don't create multiple aliasing
			let buf = unsafe {
				peripherals
					.mem
					.slice_at(sysserialwrite.buf, sysserialwrite.len)
					.unwrap_or_else(|e| {
						panic!(
							"Error {e}: Systemcall parameters for SerialWriteBuffer are invalid: {sysserialwrite:?}"
						)
					})
			};

			peripherals
				.serial
				.output(buf)
				.unwrap_or_else(|e| error!("{e:?}"))
		}
		_ => panic!("Got unknown hypercall {hypercall:?}"),
	}

	None
}

/// Translates the last error in `errno` to a value suitable to return from the hypercall.
fn translate_last_errno() -> Option<i32> {
	let errno = io::Error::last_os_error().raw_os_error()?;

	// A loop, because rust can't know for sure that errno numbers don't overlap on the host.
	macro_rules! error_pairs {
		($($x:ident),*) => {{[ $((libc::$x, hermit_abi::errno::$x)),* ]}}
	}
	for (e_host, e_guest) in error_pairs!(
		EBADF, EEXIST, EFAULT, EINVAL, EIO, EISDIR, EOVERFLOW, EPERM, ENOENT, EROFS
	) {
		if errno == e_host {
			return Some(e_guest);
		}
	}
	warn!(
		"No Hermit equivalent of host error {} (errno: {errno}), returning default to guest...",
		io::Error::from_raw_os_error(errno)
	);
	None
}
