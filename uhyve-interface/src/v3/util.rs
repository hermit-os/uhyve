use core::{fmt, marker::PhantomData, num::NonZero};

/// Largest errno that can be encoded in a [`RawResult`].
const MAX_ERRNO: u32 = i32::MAX as u32;

/// An errno as defined in [`hermit_abi::errno`](mod@hermit_abi::errno), in the range `1..=i32::MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(NonZero<u32>);
impl Errno {
	/// Returns `None` if `errno` is `0` or larger than `i32::MAX`.
	pub const fn new(errno: u32) -> Option<Self> {
		match NonZero::new(errno) {
			Some(errno) if errno.get() <= MAX_ERRNO => Some(Self(errno)),
			_ => None,
		}
	}

	pub const fn get(self) -> u32 {
		self.0.get()
	}

	/// Decodes a negative raw value, `-errno`. Returns `None` if it is out of range.
	pub(crate) fn from_raw(raw: i64) -> Option<Self> {
		u32::try_from(raw.unsigned_abs()).ok().and_then(Self::new)
	}
}

/// The value can't be represented in the ABI encoding of a [`RawResult`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotRepresentable;

/// A [`RawResult`] doesn't contain a valid result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
	/// The result is still the default value, e.g. because the host didn't handle the hypercall.
	Unset,
	/// The raw value is not a valid encoding.
	Invalid,
}

/// A result type with a numeric ABI representation, see [`RawResult`].
pub trait AbiResult: Sized {
	/// Numeric type on the ABI.
	type Repr: Copy + Eq + fmt::Debug;
	/// Raw value written before the hypercall. Must not be a valid encoding.
	const UNSET: Self::Repr;

	/// Encodes the result, failing if the value is out of range for [`Self::Repr`].
	fn encode(self) -> Result<Self::Repr, NotRepresentable>;
	/// Decodes a raw value. Returns `None` if it is not a valid encoding.
	fn decode(raw: Self::Repr) -> Option<Self>;
}

/// ABI representation of the result type `R`.
///
/// The default value marks the result as unset.
#[repr(transparent)]
pub struct RawResult<R: AbiResult>(R::Repr, PhantomData<fn() -> R>);
impl<R: AbiResult> RawResult<R> {
	/// Encodes `value`, failing if it is out of range for the ABI representation.
	pub fn encode(value: R) -> Result<Self, NotRepresentable> {
		value.encode().map(|raw| Self(raw, PhantomData))
	}

	/// Decodes the result, failing if it is unset or not a valid encoding.
	pub fn decode(self) -> Result<R, DecodeError> {
		if self.0 == R::UNSET {
			return Err(DecodeError::Unset);
		}
		R::decode(self.0).ok_or(DecodeError::Invalid)
	}
}
impl<R: AbiResult> Default for RawResult<R> {
	fn default() -> Self {
		Self(R::UNSET, PhantomData)
	}
}
impl<R: AbiResult> Clone for RawResult<R> {
	fn clone(&self) -> Self {
		*self
	}
}
impl<R: AbiResult> Copy for RawResult<R> {}
impl<R: AbiResult> PartialEq for RawResult<R> {
	fn eq(&self, other: &Self) -> bool {
		self.0 == other.0
	}
}
impl<R: AbiResult> Eq for RawResult<R> {}
impl<R: AbiResult> fmt::Debug for RawResult<R> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "RawResult({:?})", self.0)
	}
}

/// Encoded as `0` on success and `-errno` on error.
impl AbiResult for Result<(), Errno> {
	type Repr = i32;
	const UNSET: i32 = i32::MIN;

	fn encode(self) -> Result<i32, NotRepresentable> {
		Ok(match self {
			Ok(()) => 0,
			Err(errno) => -(errno.get() as i32),
		})
	}

	fn decode(raw: i32) -> Option<Self> {
		match raw {
			0 => Some(Ok(())),
			raw if raw < 0 => Errno::from_raw(raw.into()).map(Err),
			_ => None,
		}
	}
}

/// Implements [`AbiResult`] for `Result<$value, Errno>`, encoded as the value on success and
/// `-errno` on error. Negative success values are not representable.
macro_rules! value_or_errno {
	($value:ty, $signed:ty) => {
		impl AbiResult for Result<$value, Errno> {
			type Repr = $signed;
			const UNSET: $signed = <$signed>::MIN;

			fn encode(self) -> Result<$signed, NotRepresentable> {
				match self {
					Ok(value) => <$signed>::try_from(value)
						.ok()
						.filter(|raw| *raw >= 0)
						.ok_or(NotRepresentable),
					Err(errno) => Ok(-(errno.get() as $signed)),
				}
			}

			fn decode(raw: $signed) -> Option<Self> {
				if raw >= 0 {
					raw.try_into().ok().map(Ok)
				} else {
					Errno::from_raw(raw.into()).map(Err)
				}
			}
		}
	};
}

value_or_errno!(u32, i32);
value_or_errno!(i32, i32);
value_or_errno!(u64, i64);

#[cfg(test)]
mod tests {
	use super::{AbiResult, DecodeError, Errno, MAX_ERRNO, NotRepresentable, RawResult};

	fn errno(errno: u32) -> Errno {
		Errno::new(errno).unwrap()
	}

	#[test]
	fn test_errno_range() {
		assert_eq!(Errno::new(0), None);
		assert_eq!(Errno::new(MAX_ERRNO).map(Errno::get), Some(MAX_ERRNO));
		assert_eq!(Errno::new(MAX_ERRNO + 1), None);
	}

	#[test]
	fn test_unset() {
		assert_eq!(
			RawResult::<Result<(), Errno>>::default().decode(),
			Err(DecodeError::Unset)
		);
		assert_eq!(
			RawResult::<Result<u32, Errno>>::default().decode(),
			Err(DecodeError::Unset)
		);
		assert_eq!(
			RawResult::<Result<u64, Errno>>::default().decode(),
			Err(DecodeError::Unset)
		);
	}

	#[test]
	fn test_unit_result() {
		for value in [Ok(()), Err(errno(1)), Err(errno(MAX_ERRNO))] {
			assert_eq!(RawResult::encode(value).unwrap().decode(), Ok(value));
		}
		assert_eq!(<Result<(), Errno>>::decode(1), None);
	}

	#[test]
	fn test_u32_result() {
		for value in [
			Ok(0),
			Ok(i32::MAX as u32),
			Err(errno(1)),
			Err(errno(MAX_ERRNO)),
		] {
			assert_eq!(RawResult::encode(value).unwrap().decode(), Ok(value));
		}
		assert_eq!(
			RawResult::encode(Ok::<u32, Errno>(i32::MAX as u32 + 1)),
			Err(NotRepresentable)
		);
	}

	#[test]
	fn test_i32_result() {
		for value in [Ok(0), Ok(i32::MAX), Err(errno(1)), Err(errno(MAX_ERRNO))] {
			assert_eq!(RawResult::encode(value).unwrap().decode(), Ok(value));
		}
		assert_eq!(
			RawResult::encode(Ok::<i32, Errno>(-1)),
			Err(NotRepresentable)
		);
	}

	#[test]
	fn test_u64_result() {
		for value in [
			Ok(0),
			Ok(i64::MAX as u64),
			Err(errno(1)),
			Err(errno(MAX_ERRNO)),
		] {
			assert_eq!(RawResult::encode(value).unwrap().decode(), Ok(value));
		}
		assert_eq!(
			RawResult::encode(Ok::<u64, Errno>(i64::MAX as u64 + 1)),
			Err(NotRepresentable)
		);
		assert_eq!(<Result<u64, Errno>>::decode(-(MAX_ERRNO as i64) - 1), None);
	}
}
