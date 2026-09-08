use std::{
	any::Any,
	ffi::CString,
	fmt::{self, Debug},
	fs,
	path::Path,
	sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use uhyve_interface::GuestPhysAddr;

use crate::{
	HypervisorError, HypervisorResult,
	mem::GuestRamFile,
	params::{NetworkMode, Output},
	vcpu::{VcpuMailbox, VirtualCPU},
	virtio::net::VirtioNetPciDeviceSnapshot,
	vm::{KernelInfo, VirtualizationBackendInternal},
};

/// Options for a guest-triggered snapshot.
#[derive(Clone, Debug)]
pub struct SnapshotOptions {
	pub store: GuestSnapshotStore,
	/// When false, the VM stops after the snapshot is stored instead of resuming the guest.
	pub resume_after_snapshot: bool,
}

/// Slot for a guest-triggered snapshot.
#[derive(Clone, Default)]
pub struct GuestSnapshotStore {
	inner: Arc<Mutex<Option<Box<dyn Any + Send>>>>,
}
impl GuestSnapshotStore {
	pub fn new() -> Self {
		Self {
			inner: Arc::new(Mutex::new(None)),
		}
	}
}
impl fmt::Debug for GuestSnapshotStore {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("GuestSnapshotStore")
			.field("snapshot_ready", &self.snapshot_ready())
			.finish()
	}
}
impl GuestSnapshotStore {
	pub(crate) fn store_snapshot<B: VirtualizationBackendInternal + Send + 'static>(
		&self,
		snapshot: Snapshot<B>,
	) {
		*self.inner.lock().unwrap() = Some(Box::new(snapshot));
	}

	#[allow(private_bounds)]
	pub fn take_snapshot<B: VirtualizationBackendInternal + Send + 'static>(
		&self,
	) -> Option<Snapshot<B>> {
		let mut g = self.inner.lock().unwrap();
		let b = g.take()?;
		match b.downcast::<Snapshot<B>>() {
			Ok(s) => Some(*s),
			Err(restored) => {
				*g = Some(restored);
				None
			}
		}
	}

	#[allow(private_bounds)]
	pub fn save_to_disk<B: VirtualizationBackendInternal + Send + 'static>(
		&self,
		path: &Path,
	) -> HypervisorResult<()> {
		let snapshot = self.take_snapshot::<B>();
		let snapshot_bytes =
			bitcode::serialize(&snapshot).map_err(HypervisorError::SnapshotSerialize)?;
		fs::write(path, snapshot_bytes).map_err(HypervisorError::IOError)?;
		Ok(())
	}

	pub fn snapshot_ready(&self) -> bool {
		self.inner.lock().unwrap().is_some()
	}

	pub fn clear(&self) {
		*self.inner.lock().unwrap() = None;
	}
}

pub(crate) type VcpuSnapshotState<V> = <V as VirtualCPU>::SnapshotState;
type VcpuSnapshotVec<V> = Vec<VcpuSnapshotState<V>>;
pub(crate) type VcpuSnapshotMailbox<V> = VcpuMailbox<VcpuSnapshotVec<V>>;
pub(crate) type BackendVcpu<B> = <B as VirtualizationBackendInternal>::VCPU;
pub(crate) type BackendCpuSnapshotVec<B> = VcpuSnapshotVec<BackendVcpu<B>>;
pub(crate) type BackendCpuSnapshotsArc<B> = Arc<Mutex<BackendCpuSnapshotVec<B>>>;
pub(crate) type VcpuWithSnapMailbox<V> = (V, Arc<VcpuSnapshotMailbox<V>>);

#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
	// pub new_mac: Option<[u8; 6]>,
	pub new_hermit_ip: Option<CString>,
	/// New network mode to attach after restore.
	pub network: Option<NetworkMode>,
	/// Guest serial output mode. When `None`, the value stored in the snapshot is used.
	pub output: Option<Output>,
	// TODO: Env vars
	pub new_args: Option<CString>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(
	serialize = "VirtualizationBackend::SnapshotState: Serialize,
		VcpuSnapshotState<BackendVcpu<VirtualizationBackend>>: Serialize",
	deserialize = "VirtualizationBackend::SnapshotState: Deserialize<'de>,
		VcpuSnapshotState<BackendVcpu<VirtualizationBackend>>: Deserialize<'de>",
))]
#[allow(private_bounds)]
pub struct Snapshot<VirtualizationBackend: VirtualizationBackendInternal> {
	pub(crate) peripherals: VmPeripheralsSnapshot,
	pub(crate) kernel_info: KernelInfo<VirtualizationBackend::MemLayout>,
	pub(crate) cpu_snapshots: BackendCpuSnapshotVec<VirtualizationBackend>,
	pub(crate) backend: VirtualizationBackend::SnapshotState,
	/// The address of the parameters for the snapshot call, so that values can be passed back to the guest upon restore.
	pub(crate) params_addr: GuestPhysAddr,
}

/// Serializable snapshot of the guest memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemSnapshot {
	pub guest_addr: u64,
	pub data: Vec<u8>,
	/// Private RAM backing for lazy `MAP_PRIVATE` restore. Not serialized; use
	/// [`Snapshot::prepare_guest_ram_for_restore`] after loading from disk.
	#[cfg(unix)]
	#[serde(skip)]
	pub(crate) prepared: Option<GuestRamFile>,
}

/// Serializable snapshot of [`VmPeripherals`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmPeripheralsSnapshot {
	pub mem: MemSnapshot,
	pub virtio_net: Option<VirtioNetPciDeviceSnapshot>,
}

#[cfg(unix)]
impl MemSnapshot {
	pub(crate) fn ensure_prepared_ram(&mut self) -> HypervisorResult<()> {
		if self.prepared.is_some() {
			return Ok(());
		}
		self.prepared =
			Some(GuestRamFile::prepare_from_ram(&self.data).map_err(HypervisorError::IOError)?);
		Ok(())
	}
}

#[allow(private_bounds)]
impl<B: VirtualizationBackendInternal> Snapshot<B> {
	/// Fills [`MemSnapshot::prepared`] from [`MemSnapshot::data`] when absent (e.g. after
	/// deserializing from disk). In-memory snapshots from [`VmPeripherals::snapshot`] already
	/// include this.
	pub fn prepare_guest_ram_for_restore(&mut self) -> HypervisorResult<()> {
		#[cfg(unix)]
		self.peripherals.mem.ensure_prepared_ram()?;
		Ok(())
	}

	/// Serializes this snapshot with bitcode and writes it to `path`.
	pub fn write_to_path(&self, path: impl AsRef<Path>) -> HypervisorResult<()> {
		let bytes = bitcode::serialize(self).map_err(HypervisorError::SnapshotSerialize)?;
		fs::write(path.as_ref(), bytes).map_err(HypervisorError::IOError)?;
		Ok(())
	}
}
