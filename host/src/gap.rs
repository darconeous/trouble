//! ## Generic Access Profile
//!
//! This profile defines the generic procedures related to discovery of
//! Bluetooth devices (idle mode procedures) and link management aspects
//! of connecting to Bluetooth devices (connecting mode procedures).
//! It also defines procedures related to use of different security levels.
//! In addition, this profile includes common format requirements for
//! parameters accessible on the user interface level.

use embassy_sync::blocking_mutex::raw::RawMutex;
use heapless::Vec;

use crate::prelude::*;

/// Maximum length of the Device Name characteristic value.
///
/// The advertising packet is limited to 31 bytes, 9 of which are used by
/// other GAP data, so a name is worth carrying only up to 22 bytes. The
/// characteristic is backed by inline storage so that it can be updated
/// after the table is built, which bounds it at [`MAX_SMALL_DATA_SIZE`]
/// instead.
pub const DEVICE_NAME_MAX_LENGTH: usize = MAX_SMALL_DATA_SIZE;

/// The number of attributes added by the GAP and GATT services
/// GAP_SERVICE:                      1
/// ├── DEVICE_NAME:                  2
/// ├── APPEARANCE:                   2
/// └── CENTRAL_ADDRESS_RESOLUTION:   2 (security+central only)
/// GATT_SERVICE:                   + 1
/// ├── SERVICE_CHANGED:             + 3 (declaration, value, CCCD)
/// └── DATABASE_HASH:               + 2 (security only — needs AES-CMAC)
///                                 ---
///                                 = 9, 11 with security, 13 with security+central
#[cfg(not(feature = "security"))]
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 9;
/// The number of attributes added by the GAP and GATT services (with security, peripheral only)
#[cfg(all(feature = "security", not(feature = "central")))]
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 11;
/// The number of attributes added by the GAP and GATT services (with security)
#[cfg(all(feature = "security", feature = "central"))]
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 13;

/// The GAP and GATT attributes an application may need after the table is
/// built.
pub struct GapHandles {
    /// GAP Device Name (0x2A00).
    ///
    /// Writable from the application, because a device the user can rename
    /// has to be able to answer with its current name rather than the one
    /// it booted with. Clients that cached the old value are told to
    /// re-read through [`service_changed`](Self::service_changed).
    pub device_name: Characteristic<Vec<u8, DEVICE_NAME_MAX_LENGTH>>,
    /// GATT Service Changed (0x2A05).
    ///
    /// Indicating this characteristic, with the affected handle range as a
    /// pair of little-endian 16-bit handles, is the only way to make a
    /// bonded client discard a cached attribute — including a cached
    /// device name. Clients that have not subscribed are skipped.
    pub service_changed: Characteristic<[u8; 4]>,
    /// GATT Database Hash (0x2B2A), when it can be computed.
    ///
    /// A client with robust caching reads this on reconnect and rediscovers
    /// the database by itself when the value differs from the one it cached
    /// — which is what keeps a firmware update that moves handles from
    /// silently breaking every bonded peer. Unlike Service Changed it needs
    /// no indication, no subscription, and no per-bond bookkeeping.
    ///
    /// `None` without the `security` feature, whose AES-CMAC the hash is
    /// defined in terms of. Advertising a hash that cannot be computed
    /// would be worse than not having one.
    pub database_hash: Option<Characteristic<[u8; 16]>>,
}

/// Fill in values that depend on the finished table.
///
/// The database hash covers every attribute, so it cannot be known while
/// the GAP services are being added — the application's own services come
/// after. Call this once the table is complete and before serving it.
pub fn finalize_gap<M: RawMutex, const MAX: usize>(handles: &GapHandles, table: &AttributeTable<'_, M, MAX>) {
    #[cfg(feature = "security")]
    if let Some(database_hash) = handles.database_hash {
        // `hash()` reads the AES-CMAC output big-endian, while the
        // characteristic carries it least-significant octet first
        // (Core Spec Vol 3, Part G, §7.3.1).
        let _ = table.set(&database_hash, &table.hash().to_le_bytes());
    }
    #[cfg(not(feature = "security"))]
    let _ = (handles, table);
}

/// Configuration for the GAP Service.
pub enum GapConfig<'a> {
    /// Peripheral device configuration.
    Peripheral(PeripheralConfig<'a>),
    /// Central device configuration.
    Central(CentralConfig<'a>),
}

/// Configuration for a peripheral device GAP Service.
pub struct PeripheralConfig<'a> {
    /// The name of the peripheral device.
    pub name: &'a str,
    /// The representation of the external appearance of the device.
    ///
    /// Example: `&appearance::sensor::GENERIC_SENSOR.`
    pub appearance: &'a BluetoothUuid16,
    // TODO: Add more GAP parameters
    // pub preferred_connection_parameters: Option<ConnectionParameters>,
}

/// Configuration for a central device GAP Service.
pub struct CentralConfig<'a> {
    /// The name of the central device.
    pub name: &'a str,
    /// The representation of the external appearance of the device.
    ///
    /// Example: `&appearance::sensor::GENERIC_SENSOR`
    pub appearance: &'a BluetoothUuid16,
    // TODO: Add more GAP parameters
}

impl<'a> GapConfig<'a> {
    /// Create a default peripheral configuration.
    ///
    /// This configuration will use the `UNKNOWN` appearance.
    pub fn default(name: &'a str) -> Self {
        GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::UNKNOWN,
        })
    }

    /// Add the GAP config to the attribute table
    pub fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<GapHandles, &'static str> {
        match self {
            GapConfig::Peripheral(config) => config.build(table),
            GapConfig::Central(config) => config.build(table),
        }
    }
}

/// Add the GAP and GATT services shared by both roles.
fn build_gap_services<'a, M: RawMutex, const MAX: usize>(
    name: &str,
    appearance: &'a BluetoothUuid16,
    table: &mut AttributeTable<'a, M, MAX>,
) -> Result<GapHandles, &'static str> {
    let mut stored_name: Vec<u8, DEVICE_NAME_MAX_LENGTH> = Vec::new();
    stored_name
        .extend_from_slice(name.as_bytes())
        .map_err(|_| "Device name is too long")?;

    let mut gap_builder = table.add_service(Service::new(service::GAP));
    // Inline storage rather than a borrowed `&str`: the value has to remain
    // writable so a renamed device can answer with its current name.
    let device_name = gap_builder
        .add_characteristic_small(characteristic::DEVICE_NAME, [CharacteristicProp::Read], stored_name)
        .build();
    gap_builder.add_characteristic_ro(characteristic::APPEARANCE, appearance);
    #[cfg(all(feature = "security", feature = "central"))]
    gap_builder.add_characteristic_ro(characteristic::CENTRAL_ADDRESS_RESOLUTION, &1u8);
    gap_builder.build();

    let mut gatt_builder = table.add_service(Service::new(service::GATT));
    // Without this characteristic a bonded client has no way to learn that
    // anything in the table changed, and will serve its cache indefinitely.
    let service_changed = gatt_builder
        .add_characteristic_small(
            characteristic::SERVICE_CHANGED,
            [CharacteristicProp::Indicate],
            [0u8; 4],
        )
        .build();
    // Readable without encryption on purpose: a client validates its cached
    // database before it has any security, which is the whole point.
    // Populated by `finalize_gap` once the table is complete.
    #[cfg(feature = "security")]
    let database_hash = Some(
        gatt_builder
            .add_characteristic_small(characteristic::DATABASE_HASH, [CharacteristicProp::Read], [0u8; 16])
            .build(),
    );
    #[cfg(not(feature = "security"))]
    let database_hash = None;
    gatt_builder.build();

    Ok(GapHandles {
        device_name,
        service_changed,
        database_hash,
    })
}

impl<'a> PeripheralConfig<'a> {
    /// Add the peripheral GAP config to the attribute table
    fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<GapHandles, &'static str> {
        build_gap_services(self.name, self.appearance, table)
    }
}

impl<'a> CentralConfig<'a> {
    /// Add the peripheral GAP config to the attribute table
    fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<GapHandles, &'static str> {
        build_gap_services(self.name, self.appearance, table)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use super::*;

    // Building the GAP config twice must not panic. With the one-shot StaticCell
    // the second build panicked ("StaticCell already full").
    #[test]
    fn gap_config_can_be_built_twice() {
        for _ in 0..2 {
            let mut table: AttributeTable<'_, NoopRawMutex, 16> = AttributeTable::new();
            GapConfig::Peripheral(PeripheralConfig {
                name: "trouble",
                appearance: &appearance::UNKNOWN,
            })
            .build(&mut table)
            .unwrap();
        }
    }

    // The device name has to be readable back as what was configured, and
    // has to remain writable afterwards — a device that can be renamed
    // cannot answer with the name it booted with.
    #[test]
    fn device_name_is_readable_and_writable() {
        let mut table: AttributeTable<'_, NoopRawMutex, 16> = AttributeTable::new();
        let handles = GapConfig::Peripheral(PeripheralConfig {
            name: "trouble",
            appearance: &appearance::UNKNOWN,
        })
        .build(&mut table)
        .unwrap();

        assert_eq!(table.get(&handles.device_name).unwrap().as_slice(), b"trouble");

        let renamed: Vec<u8, DEVICE_NAME_MAX_LENGTH> = Vec::from_slice(b"renamed").unwrap();
        table.set(&handles.device_name, &renamed).unwrap();
        assert_eq!(table.get(&handles.device_name).unwrap().as_slice(), b"renamed");
    }

    // Service Changed exists and can be indicated, which is what makes a
    // rename visible to a client holding a cached name.
    #[test]
    fn service_changed_is_indicatable() {
        let mut table: AttributeTable<'_, NoopRawMutex, 16> = AttributeTable::new();
        let handles = GapConfig::Peripheral(PeripheralConfig {
            name: "trouble",
            appearance: &appearance::UNKNOWN,
        })
        .build(&mut table)
        .unwrap();

        assert!(handles.service_changed.props.has_cccd());
        assert!(handles.service_changed.cccd_handle.is_some());
    }

    // The hash has to describe the finished table, including services the
    // application adds after the GAP config — a hash covering only GAP
    // would never change when the parts a client actually caches do.
    #[cfg(feature = "security")]
    #[test]
    fn database_hash_covers_services_added_after_the_gap_config() {
        fn hash_with_extra_service(extra: bool) -> [u8; 16] {
            let mut table: AttributeTable<'_, NoopRawMutex, 24> = AttributeTable::new();
            let handles = GapConfig::Peripheral(PeripheralConfig {
                name: "trouble",
                appearance: &appearance::UNKNOWN,
            })
            .build(&mut table)
            .unwrap();
            if extra {
                let mut svc = table.add_service(Service::new(0x1234_u16));
                svc.add_characteristic_small(0x5678_u16, [CharacteristicProp::Read], [0u8; 2]);
                svc.build();
            }
            finalize_gap(&handles, &table);
            table.get(&handles.database_hash.unwrap()).unwrap()
        }

        let bare = hash_with_extra_service(false);
        assert_ne!(bare, [0u8; 16], "the hash was never filled in");
        assert_ne!(
            bare,
            hash_with_extra_service(true),
            "adding a service left the hash unchanged"
        );
    }

    #[test]
    fn overlong_device_name_is_rejected() {
        let too_long = "x".repeat(DEVICE_NAME_MAX_LENGTH + 1);
        let mut table: AttributeTable<'_, NoopRawMutex, 16> = AttributeTable::new();
        assert!(GapConfig::Peripheral(PeripheralConfig {
            name: &too_long,
            appearance: &appearance::UNKNOWN,
        })
        .build(&mut table)
        .is_err());
    }
}
