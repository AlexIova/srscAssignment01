# srscAssignment01

## COMMANDS

Just for ease of copy-pasting.
* StreamServer  \
`java StreamServer ./movies/monsters.dat localhost 9999`    \

Per compilare il server:    \
`javac -cp ../bcprov-jdk15on-154.jar StreamServer.java Utils.java CryptoException.java`    \

* Box   \
`java Box`

Per compilare box:    \
`javac -cp ../bcprov-jdk15on-154.jar Box.java Utils.java`    \

* openssl   \
In order to do hashes the command is:   \
`openssl dgst -sha256 <file>` with hash function    \
`openssl dgst -sha1 -hmac <mackey> <file>` for hMac \


## NOTE
Previous config:    \
localdelivery:224.7.7.7:7777    \
remote:228.10.10.10:9999    \

* Can't decrypt/encrypt with RC6/CTR/NoPadding, not available
* Can't check integrity with `SHA256` it has to be written as `SHA-256`
* Can't check integrity with `HMAC-SHA1` it has to be written as `HmacSHA1`
* Is the Box supposed to send every stream at the same time?
* The range of multicast is can be found at this link http://www.tcpipguide.com/free/t_IPMulticastAddressing.htm


## TODO

### Landmarks
- [x] Prototype

---

### Box
- [ ] Check why can't receive anything in box if address different from localhost
- [ ] Support for multicast
- [ ] Support for unicast
- [x] Parser config.properties
- [x] Parser box-cryptoconfig
- [x] PBE for box-cryptoconfig
- [ ] PBE with other algorithms
- [ ] Implement different streams and boxes
- [ ] Statistics
- [x] Refactor in different classes

---

### StreamServer
- [x] Parser movies.cryptoconfig
- [x] Decrypt movies from movies.cryptoconfing
- [x] Check integrity after decrypting
- [ ] Statistics
- [ ] Delete movie after decrypted
- [ ] Can't encrypt/decrypt with RC6/CTR/NoPadding (chekc JCE)
- [x] Refactor in different classes

--- 

## Info dump
`openssl dgst -sha256 *`    \
SHA2-256(cars.dat)= 7857c02e633edd92df139699d6f2e992062654fef85f7b47d1121037d466cc1f    \
SHA2-256(cars.dat.encrypted)= 82d5b11e1cdd26aa4d08639dc7caa27aeb5d143fd8dc4bd021881f66d16d955c  \
SHA2-256(cars.dat.encrypted.dec)= 7857c02e633edd92df139699d6f2e992062654fef85f7b47d1121037d466cc1f  \
SHA2-256(monsters.dat)= 97fccad5f83caabf499eaf71896fe1d67dca2ad9aa9bdc490d369e27ebd63751 \
SHA2-256(README)= f10fb370afa90a2a035b14e08c22afbcffacb3f7f2a5b3c013f917a2228c6b27  \
SHA2-256(world.mp4)= 7baad60681f0e480c1e3726ede92f77851fad54642e5524a4247f3c56c483503   \

`openssl dgst -sha1 -mac HMAC -macopt hexkey:<key> *`   \
HMAC-SHA1(cars.dat)= 9d404a7f8a7cb2c539d23577bf3fc63282d0c5c2   \
HMAC-SHA1(cars.dat.encrypted)= 097c200709c94fe24bf9f4cf6170c8c9be1c6060 \
HMAC-SHA1(cars.dat.encrypted.dec)= 9d404a7f8a7cb2c539d23577bf3fc63282d0c5c2 \
HMAC-SHA1(monsters.dat)= 7290bd13488321195cf729642dd60e12f94c3ca2   \
HMAC-SHA1(README)= dc0d9943ca99b00d525c379a2e79db3ab50e49a1 \
HMAC-SHA1(world.mp4)= 993dd7c7d0898777d27b4b3281b977002d38dc49  \

path.substring(path.lastIndexOf(".enc") + 1).trim()
PBEWithHmacSHA256AndAES_128
PBEWithMD5AndTripleDES