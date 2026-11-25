# Hardware checklist

Everything in this repository is tested against a simulated scale built from
the proven prototype's behaviour. These are the things only a real S200 can
confirm. Run them once, in order, and record the result here.

Set up: install the integration, enter the token, and enable debug logging
for it:

```yaml
logger:
  logs:
    custom_components.miscale: debug
```

1. **A weigh-in works with the default account id.** Step on the scale and
   stand still. Expect a *Weight* state within about 20 s and a *Weigh-in*
   event. If the session ends with no measurement while the display shows a
   weight, set the *Account id* option to your Xiaomi account id and repeat.
   That would mean the scale checks the id in the profile.
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
6. **Wrong token.** Remove the integration and add it again with one digit
   of the token changed, weigh, and expect Home Assistant to ask for the
   token again (re-authentication). Enter the right one.
7. **Battery.** After a few days of normal use, check that the scale's
   batteries are not draining faster than before; the integration
   disconnects after every weigh-in.
