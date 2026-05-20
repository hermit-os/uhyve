use std::{
	fs::File,
	io::{self, Read, Write},
	os::fd::AsFd,
};
#[cfg(target_os = "linux")]
use std::{fs::OpenOptions, io::Error, mem, os::unix::io::AsRawFd};

#[cfg(target_os = "linux")]
use libc::{IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, ifreq};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
#[cfg(target_os = "linux")]
use nix::{ifaddrs::getifaddrs, ioctl_write_int};
#[cfg(target_os = "linux")]
use virtio_bindings::bindings::virtio_net::virtio_net_hdr_v1;

use crate::net::{NetworkInterface, NetworkInterfaceRX, NetworkInterfaceTX};

pub(crate) const TUN_PATH: &str = "/dev/net/tun";
#[cfg(target_os = "linux")]
const TUN_F_CSUM: i32 = 0x01;

/// An existing (externally created) TAP device
pub struct Tap {
	fd: File,
	mac: [u8; 6],
	name: String,
	csum_offload: bool,
}

impl Tap {
	#[cfg(target_os = "linux")]
	pub fn new(iface_name: &str) -> io::Result<Self> {
		if iface_name.len() > 15 {
			return Err(Error::other("Interface name must not exceed 16 bytes"));
		}

		let (fd, csum_offload) = open_tap(iface_name)?;

		Ok(Self {
			fd,
			name: iface_name.to_string(),
			mac: lookup_mac(iface_name),
			csum_offload,
		})
	}

	pub fn csum_offload_enabled(&self) -> bool {
		self.csum_offload
	}

	#[cfg(target_os = "linux")]
	pub fn mtu(&self) -> u16 {
		use std::{fs::read, path::Path};

		read(Path::new("/sys/class/net").join(&self.name).join("mtu"))
			.ok()
			.and_then(|i| str::from_utf8(&i).ok().and_then(|s| s.parse().ok()))
			.unwrap_or(1500)
	}
}

#[cfg(target_os = "linux")]
fn open_tun() -> io::Result<File> {
	OpenOptions::new().read(true).write(true).open(TUN_PATH)
}

#[cfg(target_os = "linux")]
fn ifreq_for(name: &str) -> ifreq {
	let mut ifr_name = [0i8; 16];
	name.as_bytes()
		.iter()
		.take(15)
		.map(|b| *b as i8)
		.enumerate()
		.for_each(|(i, b)| ifr_name[i] = b);

	let flags = IFF_TAP as i16 | IFF_NO_PI as i16 | IFF_VNET_HDR as i16;

	ifreq {
		ifr_name,
		ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: flags },
	}
}

#[cfg(target_os = "linux")]
fn tun_set_iff(fd: &File, config: &ifreq) -> io::Result<()> {
	ioctl_write_int!(tun_set_iff, b'T', 202); // TUNSETIFF

	let res = unsafe {
		tun_set_iff(fd.as_raw_fd(), config as *const ifreq as u64)
			.map_err(|e| Error::other(format!("ioctl(TUNSETIFF) failed: {e}")))?
	};

	if res < 0 {
		return Err(Error::other(format!("ioctl(TUNSETIFF) returned {res}")));
	}

	Ok(())
}

/// Open a TAP device and configure it for use with virtio-net.
#[cfg(target_os = "linux")]
fn open_tap(iface_name: &str) -> io::Result<(File, bool)> {
	let fd = open_tun()?;
	tun_set_iff(&fd, &ifreq_for(iface_name))?;

	ioctl_write_int!(tun_set_vnet_hdr_sz, b'T', 216); // TUNSETVNETHDRSZ
	let vnet_hdr_size = mem::size_of::<virtio_net_hdr_v1>() as i32;
	unsafe {
		tun_set_vnet_hdr_sz(fd.as_raw_fd(), (&vnet_hdr_size as *const i32) as u64)
			.map_err(|e| Error::other(format!("ioctl(TUNSETVNETHDRSZ) failed: {e}")))?;
	}

	ioctl_write_int!(tun_set_offload, b'T', 208); // TUNSETOFFLOAD
	let csum_offload = match unsafe { tun_set_offload(fd.as_raw_fd(), TUN_F_CSUM as u64) } {
		Ok(_) => true,
		Err(e) => {
			warn!(
				"TAP `{iface_name}` lacks TUN_F_CSUM support ({e}); guest TX checksum offload disabled"
			);
			false
		}
	};

	Ok((fd, csum_offload))
}

#[cfg(target_os = "linux")]
fn lookup_mac(iface_name: &str) -> [u8; 6] {
	for ifaddr in getifaddrs().unwrap() {
		if let Some(address) = ifaddr.address
			&& ifaddr.interface_name == iface_name
			&& let Some(link_addr) = address.as_link_addr()
		{
			return link_addr.addr().unwrap();
		}
	}
	panic!("TAP device `{iface_name}` without MAC address?");
}

impl NetworkInterface for Tap {
	type RX = TapRX;
	type TX = TapTX;

	fn mac_address_as_bytes(&self) -> [u8; 6] {
		self.mac
	}

	fn split(self) -> (Self::RX, Self::TX) {
		(
			Self::RX {
				fd: self.fd.try_clone().unwrap(),
				name: self.name.clone(),
			},
			Self::TX {
				fd: self.fd.try_clone().unwrap(),
				name: self.name,
			},
		)
	}
}

pub struct TapTX {
	fd: File,
	name: String,
}
impl NetworkInterfaceTX for TapTX {
	fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
		trace!("sending {} bytes on {}", buf.len(), self.name);
		self.fd.write(buf)
	}

	#[inline]
	fn try_as_file(&mut self) -> Option<&mut File> {
		Some(&mut self.fd)
	}
}

pub(crate) fn read_file_with_timeout<F: AsFd + Read>(
	file: &mut F,
	target: &mut [u8],
	timeout: u16,
) -> io::Result<usize> {
	let mut pollfds = [PollFd::new(file.as_fd(), PollFlags::POLLIN)];
	let nready = poll::<PollTimeout>(&mut pollfds, timeout.into())?;
	if nready == 0 {
		Ok(0)
	} else {
		file.read(target)
	}
}

pub struct TapRX {
	fd: File,
	name: String,
}
impl NetworkInterfaceRX for TapRX {
	fn recv(&mut self, buf: &mut [u8], timeout: u16) -> io::Result<usize> {
		match read_file_with_timeout(&mut self.fd, buf, timeout) {
			Ok(0) => Ok(0), // Timeout
			Ok(i) => {
				trace!("receiving {i:?} bytes on {}", self.name);
				Ok(i)
			}
			Err(e) => Err(e),
		}
	}
}
