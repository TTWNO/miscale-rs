//! The GATT characteristics of the Xiaomi service (UUID `FE95`) that carry
//! the protocol.

/// A Mi BLE characteristic, identified by its 16-bit UUID in the Bluetooth
/// base UUID (`0000xxxx-0000-1000-8000-00805f9b34fb`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Channel {
    /// `0x0010`: 4-byte commands from the app and confirmations from the
    /// device (login start, login result, auth errors).
    Control,
    /// `0x0019`: parcels exchanged during login.
    Auth,
    /// `0x001A`: encrypted spec messages from the app; the device
    /// acknowledges on the same characteristic.
    SpecUp,
    /// `0x001B`: encrypted spec messages from the device; the app
    /// acknowledges on the same characteristic.
    SpecDown,
}

impl Channel {
    /// Every channel, for subscribing to notifications.
    pub const ALL: [Self; 4] = [Self::Control, Self::Auth, Self::SpecUp, Self::SpecDown];

    /// The characteristic's 16-bit UUID.
    #[must_use]
    pub const fn uuid16(self) -> u16 {
        match self {
            Self::Control => 0x0010,
            Self::Auth => 0x0019,
            Self::SpecUp => 0x001A,
            Self::SpecDown => 0x001B,
        }
    }

    /// The channel with this 16-bit UUID, if it is one of ours.
    #[must_use]
    pub const fn from_uuid16(uuid: u16) -> Option<Self> {
        match uuid {
            0x0010 => Some(Self::Control),
            0x0019 => Some(Self::Auth),
            0x001A => Some(Self::SpecUp),
            0x001B => Some(Self::SpecDown),
            _ => None,
        }
    }
}

/// One GATT write to perform: `data` to `channel`, without response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Transmit {
    /// Characteristic to write.
    pub channel: Channel,
    /// Value to write.
    pub data: crate::Packet,
}

impl Transmit {
    /// Pairs a value with its characteristic.
    #[must_use]
    pub const fn new(channel: Channel, data: crate::Packet) -> Self {
        Self { channel, data }
    }
}

#[cfg(test)]
mod tests {
    use super::Channel;

    /// UUIDs map back to their channel, and nothing else maps.
    #[test]
    fn uuid_round_trip() {
        for channel in Channel::ALL {
            assert_eq!(
                Channel::from_uuid16(channel.uuid16()),
                Some(channel),
                "{channel:?}"
            );
        }
        assert_eq!(
            Channel::from_uuid16(0x0004),
            None,
            "other FE95 characteristics"
        );
    }
}
