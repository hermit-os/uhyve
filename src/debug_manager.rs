use gdb_parser::{self, handle_packet, Handler, Response, StopReason, VCont};
use gdb_protocol::{
	io::GdbServer,
	packet::{CheckedPacket, Kind},
};
use std::cell::RefCell;
use std::io::BufReader;
use std::net::TcpStream;

/// GDBStub Implementation Details:
///
/// REMOTE_GDB <--> gdb-protocol <--> gdb_parser <--> Handler <--> vCpu
///                 ----- Arch-independent ----- | -- Arch-dependent --
///
/// - Create 'global' DebugManager, store in VM
///   - Manages gdb-protocol connection & global state
///   - Handler will get reference to global state, which might be handy if we implement multithreading support.
/// - Pass manager in an Arc to all virtual cpus
/// - on start/trap, vcpu calls `gdb_handle_exception`, which creates a `Handler`. This Handler is only responsible for the current trap on the current CPU
///   - Handler gets passed to the `DebugManager` event-loop
///      - use gdb-procotol to tell REMOTE we have stopped, wait for commands
///      - parses commands with gdb_parser, which calls the corrosponsing Handler functions
///        - Handler interacts with vcpu, eg reading/writing regs/memory
///      - Handler generates response enum. It gets turned to bytes by gdb_parser and send by gdb-protocol
///
/// - To be Host-OS/Arch flexible, both Handler and State are defined in eg `linux/gdb.rs`
///

#[cfg(target_os = "linux")]
use linux::gdb;

pub type State = gdb::State;

pub struct DebugManager {
	server: RefCell<GdbServer<BufReader<TcpStream>, TcpStream>>,
	pub state: RefCell<State>,
}

impl DebugManager {
	pub fn new(port: u32) -> Result<DebugManager, gdb_protocol::Error> {
		println!("Waiting for debugger to attach on port {}...", port);
		let server = GdbServer::listen(format!("0.0.0.0:{}", port))?;
		info!("Connected!");

		let state = State::new();

		Ok(DebugManager {
			server: RefCell::new(server),
			state: RefCell::new(state),
		})
	}

	/// main event-loop. Called from vcpu trap, loops and executes commmands until debugger tells us to continue.
	/// Do not borrow state in this func, since handler is expected to borrow/mutate it.
	pub fn handle_commands<H>(
		&self,
		handler: &mut H,
		signal: Option<StopReason>,
	) -> std::result::Result<VCont, gdb_protocol::Error>
	where
		H: Handler,
	{
		let mut server = self.server.borrow_mut();
		if let Some(signal) = signal {
			let resp = Response::Stopped(signal);
			let resp = CheckedPacket::from_data(Kind::Packet, resp.into());
			let mut bytes = Vec::new();
			resp.encode(&mut bytes).unwrap();
			debug!("OUT {:?}", std::str::from_utf8(&bytes));
			server.dispatch(&resp)?;
		}

		while let Some(packet) = server.next_packet()? {
			debug!(
				" IN {:?} {:?}",
				packet.kind,
				std::str::from_utf8(&packet.data)
			);

			let resp = match handle_packet(&packet.data, handler) {
				Ok(resp) => resp,
				Err(e) => {
					info!(
						"Could not execute command: {:?} ({:?})",
						std::str::from_utf8(&packet.data),
						e
					);
					match e {
						gdb_parser::Error::Unimplemented => Response::Empty,
						gdb_parser::Error::Error(e) => Response::Error(e),
					}
				}
			};

			// Early abort if we are continuing. Response gets send next time the handler is entered!
			if let Some(vcont) = handler.should_cont() {
				return Ok(vcont);
			}

			let resp = CheckedPacket::from_data(Kind::Packet, resp.into());
			let mut bytes = Vec::new();
			resp.encode(&mut bytes).unwrap();
			debug!("OUT {:?}", std::str::from_utf8(&bytes));
			server.dispatch(&resp)?;
		}

		info!("No next packet! Has GDB exited?");
		Ok(VCont::Continue)
	}
}
