/// Contains immutable offsets of uhyve's virtio configuration.
use super::capabilities::{
	offsets::{COMMON_CFG_OFFSET, DEVICE_CFG_OFFSET, ISR_CFG_OFFSET, NOTIFY_CFG},
	ComCfg, IsrStatus, NetDevCfg,
};
use crate::net::virtio::ConfigAddress;

// Common configuration.
pub const DEVICE_FEATURE_SELECT: ConfigAddress =
	get_offset!(COMMON_CFG_OFFSET, ComCfg, device_feature_select);

pub const DEVICE_FEATURE: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, device_feature);

pub const DRIVER_FEATURE_SELECT: ConfigAddress =
	get_offset!(COMMON_CFG_OFFSET, ComCfg, driver_feature_select);

pub const DRIVER_FEATURE: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, driver_feature);

pub const CONFIG_MSIX_VECTOR: ConfigAddress =
	get_offset!(COMMON_CFG_OFFSET, ComCfg, config_msix_vector);

pub const DEVICE_STATUS: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, device_status);

pub const QUEUE_SELECT: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_select);

pub const QUEUE_SIZE: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_size);

pub const QUEUE_MSIX_VECTOR: ConfigAddress =
	get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_msix_vector);

pub const QUEUE_ENABLE: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_enable);

pub const QUEUE_NOTIFY_OFFSET: ConfigAddress =
	get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_notify_off);

pub const QUEUE_DESC: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_desc);

pub const QUEUE_DRIVER: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_driver);

pub const QUEUE_DEVICE: ConfigAddress = get_offset!(COMMON_CFG_OFFSET, ComCfg, queue_device);

/// Notify structure in case config changes take place
pub const ISR_NOTIFY: ConfigAddress = get_offset!(ISR_CFG_OFFSET, IsrStatus, flags);

// TODO: should this really be a seperate address?
// or can we use seperate notify addresses for seperate things?
pub const MEM_NOTIFY: ConfigAddress = NOTIFY_CFG;
pub const MEM_NOTIFY_1: ConfigAddress = ConfigAddress(NOTIFY_CFG.0 + 1);

// Device configuration.
pub const MAC_ADDRESS: ConfigAddress = get_offset!(DEVICE_CFG_OFFSET, NetDevCfg, mac);
pub const MAC_ADDRESS_1: ConfigAddress = ConfigAddress(MAC_ADDRESS.0 + 4);
pub const NET_STATUS: ConfigAddress = get_offset!(DEVICE_CFG_OFFSET, NetDevCfg, status);
pub const MTU: ConfigAddress = get_offset!(DEVICE_CFG_OFFSET, NetDevCfg, mtu);
