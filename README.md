# srscAssignment01

## COMMANDS

Just for ease of copy-pasting.
* StreamServer
`java StreamServer ./movies/monsters.dat localhost 9999`

* Box
`java Box`

* openssl
In order to do hashes the command is:
`openssl dgst -sha256 <file>` with hash function
`openssl dgst -sha1 -hmac <mackey> <file>` for hMac


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

--- 

### Info dump
`openssl dgst -sha256 *`
SHA2-256(cars.dat)= 7857c02e633edd92df139699d6f2e992062654fef85f7b47d1121037d466cc1f
SHA2-256(cars.dat.encrypted)= 82d5b11e1cdd26aa4d08639dc7caa27aeb5d143fd8dc4bd021881f66d16d955c
SHA2-256(cars.dat.encrypted.dec)= 7857c02e633edd92df139699d6f2e992062654fef85f7b47d1121037d466cc1f
SHA2-256(monsters.dat)= 97fccad5f83caabf499eaf71896fe1d67dca2ad9aa9bdc490d369e27ebd63751
SHA2-256(README)= f10fb370afa90a2a035b14e08c22afbcffacb3f7f2a5b3c013f917a2228c6b27
SHA2-256(world.mp4)= 7baad60681f0e480c1e3726ede92f77851fad54642e5524a4247f3c56c483503

`openssl dgst -sha1 -hmac 6af53417a7f5e4321a65a31213048567 *`
HMAC-SHA1(cars.dat)= ea214b2fdeeca9395f7dd7cca468e08dda0201b0
HMAC-SHA1(cars.dat.encrypted)= b6c4707e8d33e555a31a298eec4e0c951ad526f4
HMAC-SHA1(cars.dat.encrypted.dec)= ea214b2fdeeca9395f7dd7cca468e08dda0201b0
HMAC-SHA1(monsters.dat)= 2084c2759e4bedaffafb8a1fbb4d69e9e739b54c
HMAC-SHA1(README)= 7ef3ad34691c8e567342d11f968f75de7f35e01c
HMAC-SHA1(world.mp4)= 537f2d536f2ac857f4d799c8268436c7ddc3b105