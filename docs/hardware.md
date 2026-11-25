# Hardware checklist

Everything in this repository is tested against a simulated scale built from
the proven prototype's behaviour. These are the things only a real S200 can
confirm. Run them once, in order, and record the result here.

Set up: install the integration, enter the token, beacon key and account ID,
and enable debug logging for it:

```yaml
logger:
  logs:
    custom_components.miscale: debug
```

1. **A weigh-in works.** Step on the scale and stand still. Expect a
   *Weight* state within about 20 s and a *Weigh-in* event. If the session
   ends with no measurement while the display shows a weight, check the
   account ID: the scale may check it.
2. **Final versus estimated.** The event's `source` should be `final`. If it
   is `estimated`, the scale never sent its stabilised value; note it.
3. **The last message is acknowledged.** Weigh twice, a few minutes apart.
   The second weigh-in should report the new weight, not repeat the first
   one, which would mean the scale replayed an unacknowledged record.
4. **A second wake-up soon after the first.** Weigh, step off, wait about a
   minute, then weigh again. Home Assistant skips advertisements that have
   not changed, so a wake-up it has not noticed as new will not start a
   session. Note how long you had to wait.
5. **Through an ESPHome proxy** (if you use one): repeat step 1 with only the
   proxy in range. Check that the proxy has `active: true` and a free
   connection slot.
6. **Wrong token.** *Reconfigure* the integration with one digit of the
   token changed, weigh, and expect Home Assistant to ask for the
   credentials again (re-authentication). Enter the right ones.
7. **Broadcast weigh-ins.** After a weigh-in, look in the debug log for
   *Broadcast weigh-in* lines. If there are any, check that the *Weigh-in*
   event still fired only once, and that the diagnostics' `scale_time`
   matches the broadcast. If a broadcast fired a second event, the
   broadcast and the connection report different timestamps; note both.
   Also note how often a weigh-in is *only* broadcast (event `source` is
   `broadcast`).
8. **Wrong beacon key.** If step 7 saw broadcasts: *Reconfigure* with one
   digit of the beacon key changed (the form checks it against the latest
   encrypted advertisement, so wait until the scale is idle), weigh, and
   expect re-authentication after the next broadcasts.
9. **Battery.** After a few days of normal use, check that the scale's
   batteries are not draining faster than before; the integration
   disconnects after every weigh-in.
