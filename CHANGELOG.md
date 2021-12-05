# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [v0.9.0] - 2021-12-03

### added

- `Pfx.address/1`, returns the address portion of given prefix without applying a mask.
- `Pfx.type/1` which returns either :ip4, :ip6, :eui48, :eui64 or the prefix.maxlen property

### fixed

- typespec for Pfx.new now includes Pfx.t as argument as well
- typespec for some others too


## [v0.8.0] - 2021-11-15

### added
- tests for `Pfx.pfxlen/1`
- added `Pfx.parse/1`
- added `Pfx.parse/2`

### changed

- type spec for `t:Pfx.prefix/t` now uses `t` instead of `Pfx.t()`

## [v0.7.0] - 2021-07-27

### added
- `Pfx.pfxlen/1` returns the number of bits in the prefix

### changed
- `Pfx.mask/2` now takes 2 options (inv_mask and trim) and trims result by default

## [v0.6.0] - 2021-07-22

### added
- `Pfx.trim/1` trims _all_ trailing zero's from given prefix
- `Pfx.mask/2` applies mask to prefix (changing its prefix.bits string)

## [v0.5.0] - 2021-07-17

### changed
- "Pfx.multicast/1"  renamed to `Pfx.multicast_decode/1` and updated decoding
- `Pfx.eui64_encode/1` now also accepts EUI-64 (only needs to flip 7th bit)

### added
- added `Pfx.first/1` as a more generic version of `Pfx.network/1`
- added `Pfx.last/1` as a more generic version of `Pfx.broadcast/1`
- added `Pfx.from_hex/1` to create a `t:Pfx.t/0` from any hex string


## [v0.4.0] - 2021-07-10

### added
- `Pfx.eui64_encode/1`, which creates a modified EUI-64 from a EUI-48 address
- `Pfx.eui64_decode/1`, which reverses a modified EUI-64 to an EUI-48 address
- `Pfx.flip/2`, which flips a single bit in bitstring
- `Pfx.insert/3`, which inserts some bits into bitstring
- `Pfx.remove/3`, which removes some bits from bitstring

### changed
- `Pfx.new/1` and `Pfx.from_mac/1` also parse EUI-64 in Cisco's dot format
- `Pfx.teredo_decode/1` mirrors the representation for server/client to its pfx argument
- functions raise their own exceptions when marshalling (instead of leaving that up to `Pfx.new/1`)

## [v0.3.0] - 2021-07-08

### added
- `Pfx.keep/2` to keep some msb bits
- `String.Chars` for MAC addresses with maxlen 64 (w/ hyphens)
- `Pfx.from_mac/1` to support EUI-64 with ":"'s

### changed
- `Pfx.new/1` now parses EUI-48 as well
- `Pfx.new/1` now parses EUI-64 as well, unless using ':' for punctuation
- `String.Chars` for MAC addresses with maxlen 48 uses hyphens
- `String.Chars` no longer accepts invalid `t:Pfx.t/0` structs
- `Pfx.format/2` without `opts`, uses same defaults as `String.Chars`

## [v0.2.1] - 2021-07-04

### added
- `Pfx.marshall/2` is now a public function

### changed
- renamed `Pfx.teredo` to `Pfx.teredo_decode/1`

## [v0.2.0] - 2021-07-03

### added
- `Pfx.teredo_encode/4`
- `Pfx.drop/2`, which drops some lsb bits
- improved documentation

## [v0.1.1] - 2021-07-03

### changed
- `Pfx.band/2`, result has same number of bits as its first argument
- `Pfx.bor/2`, result has same number of bits as its first argument
- `Pfx.bxor/2`, result has same number of bits as its first argument
- IPv6 addresses in lowercase

### fixed
- `Pfx.brot/2`, won't choke on rotating empty `pfx.bits`
- `Pfx.contrast/2`, 1.2.3.0/24 is really to the left of 1.2.4.0/24

## [v0.1.0] - 2021-06-28
- initial version
