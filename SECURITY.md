# Security policy

## Reporting a vulnerability

Please report security problems privately to Tait Hoyem
<tait@tait.tech> rather than opening a public issue. Include enough detail to
reproduce the problem. You will get an acknowledgement within a week.

## Scope and threat model

- The scale's login token and beacon key are long-lived secrets: anyone in
  Bluetooth range who has the token can read the scale, and anyone with the
  beacon key can read its broadcasts and forge them. The account ID is
  personal data. The integration stores all three in Home Assistant's config
  entry storage, never logs them, never sends the token or beacon key back
  to the browser, and redacts all three from diagnostics. A leak of any of
  them through this project is a security bug.
- Everything received over Bluetooth is untrusted. Malformed or hostile
  input must never crash Home Assistant or panic; it must fail the current
  session cleanly. Parsers are fuzzed.
- Out of scope: the scale firmware itself, Xiaomi's cloud, and the one-time
  token extraction, which happen outside this project.
