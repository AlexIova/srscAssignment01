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

Taken from other project:


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
- [ ] Decrypt movies from movies.cryptoconfing
- [ ] Check integrity after decrypting
- [ ] Statistics
- [ ] Delete movie after decrypted
- [ ] Can't encrypt/decrypt with RC6/CTR/NoPadding
