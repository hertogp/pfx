# CHANGELOG

# 0.3.0
- added `Pfx.keep/2` to keep some msb bits
- fixed `String.Chars` for MAC addresses with maxlen 48 (w/ hyphens)
- added `String.Chars` for MAC addresses with maxlen 64 (w/ hyphens)
- EUI-48 is now understood by `Pfx.new/1`
- EUI-64 is now understood by `Pfx.new/1`, if using hyphens
- added `Pfx.from_mac/1` to support EUI-64 with ":"'s
- `String.Chars` no longer accepts invalid %Pfx structs
- `Pfx.format/2` without `opts`, uses same defaults as `String.Chars`

# 0.2.1
- `Pfx.marshall/2` is now a public function
- renamed `Pfx.teredo` to `Pfx.teredo_decode/1`

# 0.2.0
- added `Pfx.teredo_encode/4`

# 0.1.2
- added `Pfx.drop/2`, which drops some lsb bits
- improved documentation

# 0.1.1
- fixed `Pfx.brot/2`, rotating empty `pfx.bits`
- fixed `Pfx.band/2`, result has same number of bits as its first argument
- fixed `Pfx.bor/2`, result has same number of bits as its first argument
- fixed `Pfx.bxor/2`, result has same number of bits as its first argument
- fixed `Pfx.contrast/2`, 1.2.3.0/24 is really to the left of 1.2.4.0/24
- IPv6 addresses in lowercase

# 0.1.0
- initial version

