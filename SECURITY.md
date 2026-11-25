# Security policy

## Reporting a vulnerability

Please report security problems privately to Tait Hoyem
<tait@tait.tech> rather than opening a public issue. Include enough detail to
reproduce the problem. You will get an acknowledgement within a week.

## Scope and threat model

- The scale's login token is a long-lived secret: anyone who has it and is in
  Bluetooth range can read the scale. The integration stores it in Home
  Assistant's config entry storage, never logs it, and redacts it from
  diagnostics. A leak of the token through this project is a security bug.
- Everything received over Bluetooth is untrusted. Malformed or hostile
  input must never crash Home Assistant or panic; it must fail the current
  session cleanly. Parsers are fuzzed.
- Out of scope: the scale firmware itself, Xiaomi's cloud, and the one-time
  token extraction, which happen outside this project.
