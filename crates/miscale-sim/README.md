# miscale-sim

A simulated Xiaomi Smart Scale S200, device side: it answers the login with
a given token, echoes the hello, accepts the profile, then plays a script of
live and final weight readings. Used to test `miscale` and the Home
Assistant integration end to end without hardware. `no_std`, sans-io.

Part of [miscale-rs](../../README.md). Licensed under MIT OR Apache-2.0.
