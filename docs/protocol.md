# The S200 weigh-in protocol

What the crates implement, byte by byte. Multi-byte integers are
little-endian unless stated otherwise.

## Sources and confidence

- The login ("standard auth") follows the published miauth and Gadgetbridge
  clients; their known-answer vectors are the tests in `mible-crypto` and
  `mible-auth`.
- The encrypted spec channel and the weigh-in were worked out from a
  capture of the official app weighing, decrypted offline with the scale's
  own token, and then proven on hardware by a Python prototype. That
  prototype is the reference this code reproduces. The decisions that
  deviate from it are listed below.
- The advertisement format and its encryption follow xiaomi-ble, Home
  Assistant's MiBeacon parser; its captured S200 weigh-in is a known-answer
  test in `mible-crypto`, `mible-beacon` and `miscale`.
- Unknown: the full grammar of spec frames (the decoders look for two
  proven patterns), the meaning of most profile fields, and whether the
  scale checks the account id (`mid`) in the profile.

## GATT

Service `FE95` (Xiaomi). Characteristics, as 16-bit UUIDs in the Bluetooth
base UUID:

| UUID   | name in the crates | carries |
|--------|--------------------|---------|
| `0010` | control  | 4-byte commands from the app, confirmations from the device |
| `0019` | auth     | login parcels, both ways |
| `001A` | spec up  | encrypted spec messages from the app; the device acknowledges here |
| `001B` | spec down| encrypted spec messages from the device; the app acknowledges here |

Every write is write-without-response. The client subscribes to
notifications on all four before its first write.

## Parcels (`mible-transport`)

A GATT value is either a **control frame** or a **fragment**. Fragment
indices start at 1, so two leading zero bytes always mean a control frame.

```text
control    00 00 <subtype> <code> [payload]
fragment   <index: u16> <payload>          (18 bytes at the default MTU)
```

| subtype | frame | layout |
|---------|-------|--------|
| 0 | announce   | `00 00 00 <kind> <count: u16>` (exactly 6 bytes) |
| 1 | ack        | `00 00 01 <status> [detail]` |
| 2 | single     | `00 00 02 <code> <payload>` (a message in one frame) |
| 3 | single-ack | `00 00 03 <code>` |
| 4, 5 | MTU negotiation | not used (the official app skips it) |

Ack status codes are the Mi BLE SDK's reliable-transfer codes: `0` success,
`1` ready, `2` busy, `3` timeout, `4` cancel, `5` lost. A *lost* ack lists the
missing fragment indices (`u16` each), so the frames other tools call
"receive timeout" (`00 00 01 05 01 00`) and "receive error"
(`00 00 01 05 03 00`) are "fragment 1 lost" and "fragment 3 lost".

Sending a parcel: announce → wait for *ready* → send the fragments → wait
for *success*; resend any fragments reported lost. Receiving: answer the
announcement with *ready*, collect the fragments in order, answer
*success*. Devices fragment to their MTU, so received fragments may be
longer than 18 bytes.

## Login (`mible-auth`, `mible-crypto`)

```text
app → control   24 00 00 00
app → auth      parcel 0x0B   app_rand (16 bytes, fresh)
dev → auth      parcel 0x0D   dev_rand (16 bytes)
dev → auth      parcel 0x0C   device proof (32 bytes)
app → auth      parcel 0x0A   app proof (32 bytes)
dev → control   21 00 00 00   logged in        (23 00 00 00: refused)
```

The device may send `E0 00 00 00` … `E3 00 00 00` at any point: an
authentication error.

Keys, with the 12-byte token:

```text
okm = HKDF-SHA256(ikm = token, salt = app_rand ‖ dev_rand,
                  info = "mible-login-info", L = 64)
dev_key = okm[0..16]    app_key = okm[16..32]
dev_iv  = okm[32..36]   app_iv  = okm[36..40]

device proof = HMAC-SHA256(dev_key, dev_rand ‖ app_rand)
app proof    = HMAC-SHA256(app_key, app_rand ‖ dev_rand)
```

A device proof that does not verify means the token is wrong; the app stops
there and never sends its own proof.

## Session cipher

```text
AES-128-CCM, 4-byte tag, no associated data
nonce = iv (4) ‖ 00 00 00 00 ‖ counter (u32)
wire  = counter (u16) ‖ ciphertext ‖ tag
```

The app seals with `app_key`/`app_iv`, counting from 0. The device seals with
`dev_key`/`dev_iv`, counting from 1. The counter travels with every message.
A counter is never reused: after 65 536 messages the channel refuses to send.

## Spec channel (`mible-spec`)

- The app sends each sealed message on `001A` as a parcel of kind `0x00`,
  even when it fits one fragment. The device acknowledges on `001A`.
- The device sends on `001B`, either as a single frame
  (`00 00 02 <code> <sealed>`, answered with `00 00 03 <code>`) or as a
  parcel. The app acknowledges every message before decrypting it.

Plaintext frames:

```text
frame    <len: u8, whole frame> 20 <seq: u16> <body>
string   <len: u8> a0 <bytes>
```

## Weigh-in (`miscale`)

```text
app   hello      seq 2, body f0                 → frame 05 20 02 00 f0
dev   echo       (any frame; the first after the hello)
app   profile    seq 3, body 05 07 01 01 01 00 ‖ string(JSON)
dev   live …     frames ending in 02 30 <centi-kg: u16>
dev   final      a string "a,b,<centi-kg>,d,<unix time>"
```

The profile goes out once the hello has been both acknowledged and echoed,
in either order. Its JSON:

```json
{"mid":"<account id>","duid":1,"uc":1,"ow":1,"unit":1,"time":<unix time>,
 "ud":[{"duid":1,"ut":1,"age":18,"sex":1,"hi":170,"wt":6000}]}
```

The scale reports its raw load cells. The user fields only feed the
official app's body-composition maths, so they are fixed.

Decoding, on the raw plaintext:

- **final**: the first string TLV that fits exactly and holds five
  comma-separated decimal numbers. The third is the weight in hundredths of
  a kilogram, the fifth the scale's timestamp of the weigh-in (Unix
  seconds by its clock). It takes precedence over a live marker.
- **live**: the frame ends in `02 30 <u16>`, the weight in hundredths of a
  kilogram.
- Anything else (device information, for example) is ignored.

If the scale never sends a final value, readings of 2.00 kg or more are kept
(the last six). When one under 1.00 kg arrives (the person stepped off), the
last five are averaged if they agree within 0.30 kg; otherwise the window is
cleared.

Timing: 10 s of silence ends the login and channel set-up, measured from the
last notification. Once the profile is acknowledged, the measurement window
is an absolute 45 s.

## Advertisements (`mible-beacon`, `miscale::beacon`)

The scale advertises MiBeacon service data under UUID `FE95`:

```text
frame control  u16       flags; version in bits 12–15 (the S200: 5)
product id     u16       the S200: 0x45C9, 0x4C04 or 0x4DCB
frame counter  u8        changes with each new advertisement
MAC            6 bytes   reversed; if flag bit 4
capability     u8 [u8]   if flag bit 5; an I/O byte if capability bit 5
objects        …         if flag bit 6; encrypted if flag bit 3:
                         ciphertext ‖ extended counter (3) ‖ tag (4)
```

An object is `id (u16) ‖ length (u8) ‖ data`. Encrypted objects (v4/v5) use
AES-128-CCM under the beacon key, with a 4-byte tag, associated data `11`,
and the nonce

```text
MAC (6, reversed) ‖ product id (u16) ‖ frame counter ‖ extended counter (3)
```

The tag does not cover the frame control or capability bytes; only what
decrypts is trusted.

Idle advertisements carry no objects. Once a weight is final, the scale
broadcasts it as object `0x4E16`:

```text
profile (u8) ‖ weight (u32, hundredths of a kg) ‖ scale time (u32)
```

The scale time is the same timestamp as in the final reading over the
connection.

## Deliberate deviations from the prototype

- Lost fragments are resent; the prototype treated those acks as errors.
- Unexpected or duplicate acks are ignored, and oversized messages are
  acknowledged and dropped instead of failing the session.
- The stabiliser compares integer hundredths of a kilogram. The prototype
  compared floats and rejected about half of the spreads of exactly 0.30 kg
  by rounding error.
- After a failure the session sends nothing more, including any pending
  acknowledgement. After a measurement it still acknowledges the scale's
  last message.
