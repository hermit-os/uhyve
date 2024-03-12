//! General paging related code
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PagetableError {
	#[error("The accessed virtual address is not mapped")]
	InvalidAddress,
}
