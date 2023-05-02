//! This file contains the entry point to the Hypervisor. The Uhyve utilizes KVM to
//! create a Virtual Machine and load the kernel.

use std::{
	cmp,
	ffi::OsString,
	fmt, hint, mem,
	os::raw::c_void,
	path::{Path, PathBuf},
	ptr::{self, read_volatile, write_volatile},
	sync::{mpsc::sync_channel, Arc, Mutex},
	thread,
};

use hermit_entry::boot_info::RawBootInfo;
use kvm_bindings::*;
use kvm_ioctls::VmFd;
use log::debug;
use nix::sys::mman::*;
use tun_tap::{Iface, Mode};
use vmm_sys_util::eventfd::EventFd;
use x86_64::{
	structures::paging::{Page, PageTable, PageTableFlags, Size2MiB},
	PhysAddr,
};

use crate::{
	consts::*,
	linux::{vcpu::*, virtio::*, KVM},
	params::Params,
	shared_queue::*,
	vm::{HypervisorResult, Vm},
	x86_64::create_gdt_entry,
};

const KVM_32BIT_MAX_MEM_SIZE: usize = 1 << 32;
const KVM_32BIT_GAP_SIZE: usize = 768 << 20;
const KVM_32BIT_GAP_START: usize = KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE;

#[derive(Debug)]
struct UhyveNetwork {
	#[allow(dead_code)]
	reader: std::thread::JoinHandle<()>,
	#[allow(dead_code)]
	writer: std::thread::JoinHandle<()>,
	tx: std::sync::mpsc::SyncSender<usize>,
}

impl UhyveNetwork {
	pub fn new(evtfd: EventFd, start: usize) -> Self {
		let iface = Arc::new(
			Iface::without_packet_info("", Mode::Tap).expect("Unable to creat TUN/TAP device"),
		);

		let iface_writer = Arc::clone(&iface);
		let iface_reader = Arc::clone(&iface);
		let (tx, rx) = sync_channel(1);

		let writer = thread::spawn(move || {
			let tx_queue = unsafe {
				#[allow(clippy::cast_ptr_alignment)]
				&mut *((start + align_up!(mem::size_of::<SharedQueue>(), 64)) as *mut u8
					as *mut SharedQueue)
			};
			tx_queue.init();

			loop {
				let _value = rx.recv().expect("Failed to read from channel");

				let written = unsafe { read_volatile(&tx_queue.written) };
				let read = unsafe { read_volatile(&tx_queue.read) };
				let distance = written - read;

				if distance > 0 {
					let idx = read % UHYVE_QUEUE_SIZE;
					let len = unsafe { read_volatile(&tx_queue.inner[idx].len) } as usize;
					let _ = iface_writer
						.send(&tx_queue.inner[idx].data[0..len])
						.expect("Send on TUN/TAP device failed!");

					unsafe { write_volatile(&mut tx_queue.read, read + 1) };
				}
			}
		});

		let reader = thread::spawn(move || {
			let rx_queue = unsafe {
				#[allow(clippy::cast_ptr_alignment)]
				&mut *(start as *mut u8 as *mut SharedQueue)
			};
			rx_queue.init();

			loop {
				let written = unsafe { read_volatile(&rx_queue.written) };
				let read = unsafe { read_volatile(&rx_queue.read) };
				let distance = written - read;

				if distance < UHYVE_QUEUE_SIZE {
					let idx = written % UHYVE_QUEUE_SIZE;
					unsafe {
						write_volatile(
							&mut rx_queue.inner[idx].len,
							iface_reader
								.recv(&mut rx_queue.inner[idx].data)
								.expect("Receive on TUN/TAP device failed!")
								.try_into()
								.unwrap(),
						);
						write_volatile(&mut rx_queue.written, written + 1);
					}

					evtfd.write(1).expect("Unable to trigger interrupt");
				} else {
					hint::spin_loop();
				}
			}
		});

		UhyveNetwork { reader, writer, tx }
	}
}

pub struct Uhyve {
	vm: VmFd,
	offset: u64,
	entry_point: u64,
	stack_address: u64,
	mem: MmapMemory,
	num_cpus: u32,
	path: PathBuf,
	args: Vec<OsString>,
	boot_info: *const RawBootInfo,
	uhyve_device: Option<UhyveNetwork>,
	virtio_device: Arc<Mutex<VirtioNetPciDevice>>,
	pub(super) gdb_port: Option<u16>,
}

impl fmt::Debug for Uhyve {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Uhyve")
			.field("entry_point", &self.entry_point)
			.field("stack_address", &self.stack_address)
			.field("mem", &self.mem)
			.field("num_cpus", &self.num_cpus)
			.field("path", &self.path)
			.field("boot_info", &self.boot_info)
			.field("uhyve_device", &self.uhyve_device)
			.field("virtio_device", &self.virtio_device)
			.finish()
	}
}

impl Uhyve {
	pub fn new(kernel_path: PathBuf, params: Params) -> HypervisorResult<Uhyve> {
		let memory_size = params.memory_size.get();

		let vm = KVM.create_vm()?;

		let mem = MmapMemory::new(0, memory_size, 0, params.thp, params.ksm);

		let sz = cmp::min(memory_size, KVM_32BIT_GAP_START);

		// create virtio interface
		let virtio_device = Arc::new(Mutex::new(VirtioNetPciDevice::new()));

		let kvm_mem = kvm_userspace_memory_region {
			slot: 0,
			flags: mem.flags,
			memory_size: sz as u64,
			guest_phys_addr: mem.guest_address as u64,
			userspace_addr: mem.host_address as u64,
		};

		unsafe { vm.set_user_memory_region(kvm_mem) }?;

		if memory_size > KVM_32BIT_GAP_START + KVM_32BIT_GAP_SIZE {
			let kvm_mem = kvm_userspace_memory_region {
				slot: 1,
				flags: mem.flags,
				memory_size: (memory_size - KVM_32BIT_GAP_START - KVM_32BIT_GAP_SIZE) as u64,
				guest_phys_addr: (mem.guest_address + KVM_32BIT_GAP_START + KVM_32BIT_GAP_SIZE)
					as u64,
				userspace_addr: (mem.host_address + KVM_32BIT_GAP_START + KVM_32BIT_GAP_SIZE)
					as u64,
			};

			unsafe { vm.set_user_memory_region(kvm_mem) }?;
		}

		debug!("Initialize interrupt controller");

		// create basic interrupt controller
		vm.create_irq_chip()?;

		if params.pit {
			vm.create_pit2(kvm_pit_config::default()).unwrap();
		}

		// enable x2APIC support
		let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_X2APIC_API,
			flags: 0,
			..Default::default()
		};
		cap.args[0] =
			(KVM_X2APIC_API_USE_32BIT_IDS | KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK).into();
		vm.enable_cap(&cap)
			.expect("Unable to enable x2apic support");

		// currently, we support only system, which provides the
		// cpu feature TSC_DEADLINE
		let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_TSC_DEADLINE_TIMER,
			..Default::default()
		};
		cap.args[0] = 0;
		vm.enable_cap(&cap)
			.expect_err("Processor feature `tsc deadline` isn't supported!");

		let cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_IRQFD,
			..Default::default()
		};
		vm.enable_cap(&cap)
			.expect_err("The support of KVM_CAP_IRQFD is currently required");

		let mut cap: kvm_enable_cap = kvm_bindings::kvm_enable_cap {
			cap: KVM_CAP_X86_DISABLE_EXITS,
			flags: 0,
			..Default::default()
		};
		cap.args[0] =
			(KVM_X86_DISABLE_EXITS_PAUSE | KVM_X86_DISABLE_EXITS_MWAIT | KVM_X86_DISABLE_EXITS_HLT)
				.into();
		vm.enable_cap(&cap)
			.expect("Unable to disable exists due pause instructions");

		let evtfd = EventFd::new(0).unwrap();
		vm.register_irqfd(&evtfd, UHYVE_IRQ_NET)?;
		// create TUN/TAP device
		let uhyve_device =
			false.then(|| UhyveNetwork::new(evtfd, mem.host_address + SHAREDQUEUE_START));

		let cpu_count = params.cpu_count.get();

		assert!(
			params.gdb_port.is_none() || cpu_count == 1,
			"gdbstub is only supported with one CPU"
		);

		let hyve = Uhyve {
			vm,
			offset: 0,
			entry_point: 0,
			stack_address: 0,
			mem,
			num_cpus: cpu_count,
			path: kernel_path,
			args: params.kernel_args,
			boot_info: ptr::null(),
			uhyve_device,
			virtio_device,
			gdb_port: params.gdb_port,
		};

		hyve.init_guest_mem();

		Ok(hyve)
	}
}

impl Vm for Uhyve {
	fn set_offset(&mut self, offset: u64) {
		self.offset = offset;
	}

	fn get_offset(&self) -> u64 {
		self.offset
	}

	fn set_entry_point(&mut self, entry: u64) {
		self.entry_point = entry;
	}

	fn get_entry_point(&self) -> u64 {
		self.entry_point
	}

	fn set_stack_address(&mut self, stack_addresss: u64) {
		self.stack_address = stack_addresss;
	}

	fn stack_address(&self) -> u64 {
		self.stack_address
	}

	fn num_cpus(&self) -> u32 {
		self.num_cpus
	}

	fn guest_mem(&self) -> (*mut u8, usize) {
		(self.mem.host_address as *mut u8, self.mem.memory_size)
	}

	fn kernel_path(&self) -> &Path {
		self.path.as_path()
	}

	fn create_cpu(&self, id: u32) -> HypervisorResult<UhyveCPU> {
		let tx = self.uhyve_device.as_ref().map(|dev| dev.tx.clone());

		Ok(UhyveCPU::new(
			id,
			self.path.clone(),
			self.args.clone(),
			self.vm.create_vcpu(id.try_into().unwrap())?,
			self.mem.host_address,
			tx,
			self.virtio_device.clone(),
		))
	}

	fn set_boot_info(&mut self, header: *const RawBootInfo) {
		self.boot_info = header;
	}

	/// Initialize the page tables for the guest
	fn init_guest_mem(&self) {
		debug!("Initialize guest memory");

		let (mem_addr, _) = self.guest_mem();

		unsafe {
			let pml4 = &mut *((mem_addr as u64 + BOOT_PML4) as *mut PageTable);
			let pdpte = &mut *((mem_addr as u64 + BOOT_PDPTE) as *mut PageTable);
			let pde = &mut *((mem_addr as u64 + BOOT_PDE) as *mut PageTable);
			let gdt_entry: u64 = mem_addr as u64 + BOOT_GDT;

			// initialize GDT
			*((gdt_entry) as *mut u64) = create_gdt_entry(0, 0, 0);
			*((gdt_entry + mem::size_of::<*mut u64>() as u64) as *mut u64) =
				create_gdt_entry(0xA09B, 0, 0xFFFFF); /* code */
			*((gdt_entry + 2 * mem::size_of::<*mut u64>() as u64) as *mut u64) =
				create_gdt_entry(0xC093, 0, 0xFFFFF); /* data */

			/* For simplicity we currently use 2MB pages and only a single
			PML4/PDPTE/PDE. */

			// per default is the memory zeroed, which we allocate by the system call mmap
			/*libc::memset(pml4 as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
			libc::memset(pdpte as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);
			libc::memset(pde as *mut _ as *mut libc::c_void, 0x00, PAGE_SIZE);*/

			pml4[0].set_addr(
				PhysAddr::new(BOOT_PDPTE),
				PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
			);
			pml4[511].set_addr(
				PhysAddr::new(BOOT_PML4),
				PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
			);
			pdpte[0].set_addr(
				PhysAddr::new(BOOT_PDE),
				PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
			);

			for i in 0..512 {
				let addr = PhysAddr::new(i as u64 * Page::<Size2MiB>::SIZE);
				pde[i].set_addr(
					addr,
					PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE,
				);
			}
		}
	}
}

// TODO: Investigate soundness
// https://github.com/hermitcore/uhyve/issues/229
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for Uhyve {}
unsafe impl Sync for Uhyve {}

#[derive(Debug)]
struct MmapMemory {
	flags: u32,
	memory_size: usize,
	guest_address: usize,
	host_address: usize,
}

impl MmapMemory {
	pub fn new(
		flags: u32,
		memory_size: usize,
		guest_address: u64,
		huge_pages: bool,
		mergeable: bool,
	) -> MmapMemory {
		let host_address = unsafe {
			mmap(
				None,
				memory_size.try_into().unwrap(),
				ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
				MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_NORESERVE,
				-1,
				0,
			)
			.expect("mmap failed")
		};

		if mergeable {
			debug!("Enable kernel feature to merge same pages");
			unsafe {
				madvise(host_address, memory_size, MmapAdvise::MADV_MERGEABLE).unwrap();
			}
		}

		if huge_pages {
			debug!("Uhyve uses huge pages");
			unsafe {
				madvise(host_address, memory_size, MmapAdvise::MADV_HUGEPAGE).unwrap();
			}
		}

		MmapMemory {
			flags,
			memory_size,
			guest_address: guest_address as usize,
			host_address: host_address as usize,
		}
	}

	#[allow(dead_code)]
	fn as_slice_mut(&mut self) -> &mut [u8] {
		unsafe { std::slice::from_raw_parts_mut(self.host_address as *mut u8, self.memory_size) }
	}
}

impl Drop for MmapMemory {
	fn drop(&mut self) {
		if self.memory_size > 0 {
			unsafe {
				munmap(self.host_address as *mut c_void, self.memory_size).unwrap();
			}
		}
	}
}
