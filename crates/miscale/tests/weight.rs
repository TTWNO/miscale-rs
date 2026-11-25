//! Weight decoding and the stabiliser, against the prototype's rules.
#![cfg(test)]

use miscale::weight::{FinalReading, Reading, Stabiliser, Weight, decode, decode_final};

/// A final frame holds `<len> a0 "a,b,<centi-kg>,d,e"` somewhere.
#[test]
fn final_frames() {
    let mut frame = heapless::Vec::<u8, 64>::new();
    frame
        .extend_from_slice(&[0x22, 0x20, 0x09, 0x00, 0x01, 0x02])
        .unwrap();
    let text = b"0,0,8360,2,1764000000";
    frame.push(u8::try_from(text.len()).unwrap()).unwrap();
    frame.push(0xa0).unwrap();
    frame.extend_from_slice(text).unwrap();
    let reading = FinalReading::new(Weight(8360), 1_764_000_000);
    assert_eq!(decode_final(&frame), Some(reading), "final");
    assert_eq!(decode(&frame), Some(Reading::Final(reading)), "decode");
}

/// Final wins over a coincidental live marker; exact-fit and the five
/// numeric fields are required.
#[test]
fn final_rules() {
    let with_live_tail = [
        &[3_u8, 0xa0][..],
        b"9,9",
        &[0x0c, 0xa0],
        b"1,2,5545,4,5",
        &[0x02, 0x30, 0x10, 0x00],
    ]
    .concat();
    assert_eq!(
        decode(&with_live_tail),
        Some(Reading::Final(FinalReading::new(Weight(5545), 5))),
        "final precedence"
    );
    assert_eq!(
        decode_final(&[&[12_u8, 0xa0][..], b"1,2,5545,4,5"].concat()),
        Some(FinalReading::new(Weight(5545), 5)),
        "fits"
    );
    assert_eq!(
        decode_final(&[&[13_u8, 0xa0][..], b"1,2,5545,4,5"].concat()),
        None,
        "overrun"
    );
    assert_eq!(
        decode_final(&[&[13_u8, 0xa0][..], b"1,2,5545,4,5\n"].concat()),
        Some(FinalReading::new(Weight(5545), 5)),
        "newline"
    );
    assert_eq!(
        decode_final(&[&[11_u8, 0xa0][..], b"1,2,5545,45"].concat()),
        None,
        "four fields"
    );
    assert_eq!(
        decode_final(&[&[14_u8, 0xa0][..], b"1,2,5545,4,5,6"].concat()),
        None,
        "six fields"
    );
    assert_eq!(
        decode_final(&[&[12_u8, 0xa0][..], b"1,2,55x5,4,5"].concat()),
        None,
        "non-digit"
    );
    assert_eq!(
        decode_final(&[&[11_u8, 0xa0][..], b"1,,5545,4,5"].concat()),
        None,
        "empty field"
    );
    assert_eq!(
        decode_final(&[&[18_u8, 0xa0][..], b"1,2,99999999999,4,5"].concat()),
        None,
        "weight over u32"
    );
    assert_eq!(
        decode_final(&[&[21_u8, 0xa0][..], b"1,2,5545,4,4294967296"].concat()),
        None,
        "time over u32"
    );
    assert_eq!(
        decode_final(&[&[21_u8, 0xa0][..], b"1,2,5545,4,4294967295"].concat()),
        Some(FinalReading::new(Weight(5545), u32::MAX)),
        "time at u32::MAX"
    );
}

/// Feeds a sequence of centi-kg readings; returns the estimate, if any.
fn feed(readings: &[u32]) -> Option<Weight> {
    let mut stabiliser = Stabiliser::new();
    readings
        .iter()
        .find_map(|&centi| stabiliser.push(Weight(centi)))
}

/// The prototype's stabilisation rule.
#[test]
fn stabiliser_rules() {
    assert_eq!(
        feed(&[8350, 8360, 8355, 8358, 8362, 50]),
        Some(Weight(8357)),
        "steady then off"
    );
    assert_eq!(
        feed(&[8350, 8360, 8355, 8358, 50]),
        None,
        "only four loaded readings"
    );
    assert_eq!(
        feed(&[8000, 8350, 8360, 8355, 8358, 8362, 50]),
        Some(Weight(8357)),
        "oldest dropped"
    );
    assert_eq!(
        feed(&[8300, 8360, 8355, 8358, 8362, 50]),
        None,
        "spread 0.62 kg"
    );
    assert_eq!(
        feed(&[8330, 8360, 8340, 8350, 8345, 50]),
        Some(Weight(8345)),
        "spread exactly 0.30 kg"
    );
    assert_eq!(
        feed(&[8350, 8360, 150, 8355, 8358, 8362, 50]),
        Some(Weight(8357)),
        "1-2 kg ignored"
    );
    assert_eq!(
        feed(&[8350, 8360, 8355, 8358, 8362, 100]),
        None,
        "1.00 kg is not off"
    );
    assert_eq!(
        feed(&[8350, 8360, 8355, 8358, 8362, 199]),
        None,
        "1.99 kg ignored"
    );
    assert_eq!(
        feed(&[
            8300, 8360, 8355, 8358, 8362, 50, 6000, 6001, 6002, 6003, 6004, 0
        ]),
        Some(Weight(6002)),
        "cleared after a bad spread"
    );
}

/// The mean rounds half up: 8357.4 → 8357, 8357.6 → 8358.
#[test]
fn stabiliser_rounding() {
    assert_eq!(
        feed(&[8357, 8357, 8357, 8358, 8358, 0]),
        Some(Weight(8357)),
        "x.4 down"
    );
    assert_eq!(
        feed(&[8357, 8358, 8358, 8358, 8358, 0]),
        Some(Weight(8358)),
        "x.8 up"
    );
    assert_eq!(
        feed(&[8357, 8357, 8357, 8357, 8359, 0]),
        Some(Weight(8357)),
        "x.4 down again"
    );
    assert_eq!(
        feed(&[8357, 8357, 8358, 8358, 8360, 0]),
        Some(Weight(8358)),
        "x.0"
    );
}
