//! Property tests for the frame codec.
#![cfg(test)]

use mible_beacon::{Advertisement, Body, DecryptError, FrameControl, Header};
use mible_crypto::{BeaconCipher, BeaconKey};
use proptest::prelude::*;

/// Largest frame the tests build.
const MAX: usize = 64;

/// Strategy for headers `encode_plain` accepts, from version `min_version`.
fn header(min_version: u16) -> impl Strategy<Value = Header> {
    (
        min_version..16,
        any::<u16>(),
        any::<u16>(),
        any::<u8>(),
        proptest::option::of(any::<[u8; 6]>()),
        proptest::option::of((any::<u8>(), any::<u8>())),
    )
        .prop_map(|(version, flags, product_id, counter, mac, capability)| {
            // Keep the version; never set the mesh flag.
            let bits = (version << 12_u16) | (flags & 0x0fff & !FrameControl::MESH);
            let mut header = Header::new(FrameControl::from_bits(bits), product_id, counter);
            header.mac = mac;
            if let Some((capability, io)) = capability {
                header.capability = Some(capability);
                header.io_capability = (capability & 0x20 != 0).then_some(io);
            }
            header
        })
}

/// What `parse` reports for a header `encode` wrote.
fn normalised(header: &Header, objects: bool, encrypted: bool) -> FrameControl {
    header
        .frame_control
        .with(FrameControl::MAC, header.mac.is_some())
        .with(FrameControl::CAPABILITY, header.capability.is_some())
        .with(FrameControl::OBJECTS, objects)
        .with(FrameControl::ENCRYPTED, encrypted)
}

proptest! {
    /// Parsing arbitrary bytes never panics, and decrypting whatever parses
    /// never panics either.
    #[test]
    fn parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..MAX)) {
        if let Ok(adv) = Advertisement::parse(&data) {
            let cipher = BeaconCipher::new(&BeaconKey::new([0; 16]));
            let mut out = heapless::Vec::<u8, MAX>::new();
            let _ignored: Result<(), DecryptError> = adv.decrypt(&cipher, [0; 6], &mut out);
        }
    }

    /// Plain frames parse back to what was encoded.
    #[test]
    fn plain_round_trip(
        header in header(2),
        objects in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..20)),
    ) {
        let mut out = heapless::Vec::<u8, MAX>::new();
        Advertisement::encode_plain(&header, objects.as_deref(), &mut out).unwrap();
        let adv = Advertisement::parse(&out).unwrap();
        let mut expected = header;
        expected.frame_control = normalised(&header, objects.is_some(), false);
        prop_assert_eq!(adv.header, expected);
        prop_assert_eq!(adv.body, objects.as_deref().map_or(Body::Empty, Body::Plain));
    }

    /// Sealed frames decrypt back to their objects with the same key and
    /// address, and changing any authenticated byte is caught: the product
    /// id, frame counter, MAC, objects, extended counter and tag. (The frame
    /// control and capability bytes are not authenticated.)
    #[test]
    fn sealed_round_trip(
        header in header(4),
        objects in proptest::collection::vec(any::<u8>(), 0..20),
        key in any::<[u8; 16]>(),
        address in any::<[u8; 6]>(),
        ext_counter in any::<[u8; 3]>(),
        flip in any::<prop::sample::Index>(),
        bit in 0_u8..8,
    ) {
        let mut header = header;
        header.mac = header.mac.map(|_| address);
        let cipher = BeaconCipher::new(&BeaconKey::new(key));
        let mut out = heapless::Vec::<u8, MAX>::new();
        Advertisement::encode_sealed(&header, &objects, &cipher, address, ext_counter, &mut out)
            .unwrap();
        let adv = Advertisement::parse(&out).unwrap();
        prop_assert_eq!(adv.header.frame_control, normalised(&header, true, true));
        let mut plain = heapless::Vec::<u8, MAX>::new();
        adv.decrypt(&cipher, address, &mut plain).unwrap();
        prop_assert_eq!(plain.as_slice(), objects.as_slice());

        let mac_end: usize = if header.mac.is_some() { 11 } else { 5 };
        let payload_start = [header.capability, header.io_capability]
            .iter()
            .flatten()
            .fold(mac_end, |at, _| at.saturating_add(1));
        let authenticated: Vec<usize> = (2..mac_end).chain(payload_start..out.len()).collect();
        let at = authenticated[flip.index(authenticated.len())];
        let mut tampered = out.clone();
        tampered[at] ^= 1 << bit;
        let tampered = Advertisement::parse(&tampered).unwrap();
        let result = tampered.decrypt(&cipher, address, &mut plain);
        prop_assert!(result.is_err(), "tampered byte {} accepted", at);
        prop_assert!(plain.is_empty());
    }
}
