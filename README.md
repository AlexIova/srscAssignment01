# srscAssignment01

## COMMANDS

Just for ease of copy-pasting.
* StreamServer
`java StreamServer ./movies/monsters.dat localhost 9999`

* Box
`java Box`

* openssl


## NOTE
Previous config:
localdelivery:224.7.7.7:7777
remote:228.10.10.10:9999

* Can't decrypt/encrypt with RC6/CTR/NoPadding, not available
* Can't check integrity with `SHA256` it has to be written as `SHA-256`
* Can't check integrity with `HMAC-SHA1` it has to be written as `HmacSHA1`


## TODO

### Landmarks
- [x] Prototype

---

### Box
- [ ] Check why can't receive anything in box if address different from localhost
- [ ] Support for multicast
- [ ] Support for unicast
- [ ] Statistics

---

### StreamServer
- [x] Parser movies.cryptoconfig
- [x] Decrypt movies from movies.cryptoconfing
- [ ] Check integrity after decrypting
- [ ] Statistics
- [ ] Delete movie after decrypted
- [ ] Can't encrypt/decrypt with RC6/CTR/NoPadding
