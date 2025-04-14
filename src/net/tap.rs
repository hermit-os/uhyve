use std::{
	fs::{File, OpenOptions},
	io::{self, Error, Read, Write},
	os::unix::io::AsRawFd,
	sync::Mutex,
};

use libc::{IFF_NO_PI, IFF_TAP, ifreq};
use nix::{ifaddrs::getifaddrs, ioctl_write_int};

use crate::net::NetworkInterface;

/// An existing (externally created) TAP device
pub struct Tap {
	fd: File,
	mac: [u8; 6],
	name: String,
}

impl Tap {
	pub fn new() -> io::Result<Self> {
		let iface_name = std::env::var("TAP").unwrap_or("tap10".to_owned());
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
			if let Some(address) = ifaddr.address {
				if ifaddr.interface_name == iface_name {
					if let Some(link_addr) = address.as_link_addr() {
						mac_addr = Some(link_addr.addr().unwrap());
					}
				}
			}
		}

		Ok(Self {
			fd,
			name: iface_name,
			mac: mac_addr.expect("TAP device without MAC address?"),
		})
	}
}
impl NetworkInterface for Mutex<Tap> {
	fn mac_address_as_bytes(&self) -> [u8; 6] {
		self.lock().unwrap().mac
	}

	fn send(&self, buf: &[u8]) -> io::Result<usize> {
		let mut guard = self.lock().unwrap();
		trace!("sending {} bytes on {}", buf.len(), guard.name);
		guard.fd.write(buf)
	}

	fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
		let mut guard = self.lock().unwrap();
		let res = guard.fd.read(buf);
		trace!("receiving {res:?} bytes on {}", guard.name);
		res
	}
}
