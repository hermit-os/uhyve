use std::{
	fs::{File, OpenOptions},
	io::{self, Error, Read, Write},
	os::{fd::AsFd, unix::io::AsRawFd},
};

use libc::{IFF_NO_PI, IFF_TAP, ifreq};
use nix::{
	ifaddrs::getifaddrs,
	ioctl_write_int,
	poll::{PollFd, PollFlags, PollTimeout, poll},
};

use crate::net::{NetworkInterface, NetworkInterfaceRX, NetworkInterfaceTX};

/// An existing (externally created) TAP device
pub struct Tap {
	fd: File,
	mac: [u8; 6],
	name: String,
}

impl Tap {
	pub fn new(iface_name: &str) -> io::Result<Self> {
		if iface_name.len() > 16 {
			return Err(Error::other("Interface name must not exceed 16 bytes"));
		}
		let mut ifr_name: [i8; 16] = [0; 16];
		iface_name
			.as_bytes()
			.iter()
			.take(15)
			.map(|b| *b as i8)
			.enumerate()
			.for_each(|(i, b)| ifr_name[i] = b);

		let config_str = ifreq {
			ifr_name,
			ifr_ifru: libc::__c_anonymous_ifr_ifru {
				ifru_flags: IFF_TAP as i16 | IFF_NO_PI as i16, // TODO: Investigate if IFF_NO_PI is necessary as well
			},
		};

		let fd = OpenOptions::new()
			.read(true)
			.write(true)
			.open("/dev/net/tun")?;

		ioctl_write_int!(tun_set_iff, b'T', 202);

		let res =
			unsafe { tun_set_iff(fd.as_raw_fd(), &config_str as *const ifreq as u64).unwrap() };

		if res == -1 {
			error!("Can't open TAP device {iface_name}");
			return Err(Error::other("Can't open TAP device"));
		}

		// Find MAC address of the TAP device
		let mut mac_addr = None;
		for ifaddr in getifaddrs().unwrap() {
			if let Some(address) = ifaddr.address
				&& ifaddr.interface_name == iface_name
				&& let Some(link_addr) = address.as_link_addr()
			{
				mac_addr = Some(link_addr.addr().unwrap());
			}
		}

		Ok(Self {
			fd,
			name: iface_name.to_string(),
			mac: mac_addr.expect("TAP device without MAC address?"),
		})
	}
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
				name: self.name.clone(),
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
