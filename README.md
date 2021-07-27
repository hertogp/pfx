# Pfx

[![Test](https://github.com/hertogp/pfx/actions/workflows/elixir.yml/badge.svg)](https://github.com/hertogp/pfx/actions/workflows/elixir.yml)
[![Module Version](https://img.shields.io/hexpm/v/pfx.svg)](https://hex.pm/packages/pfx)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/pfx/)
[![Last Updated](https://img.shields.io/github/last-commit/hertogp/pfx.svg)](https://github.com/hertogp/pfx/commits/main)
[![License](https://img.shields.io/hexpm/l/pfx.svg)](https://github.com/hertogp/pfx/blob/master/LICENSE.md)
[![Total Download](https://img.shields.io/hexpm/dt/pfx.svg)](https://hex.pm/packages/pfx)

<!-- @MODULEDOC -->

Functions to make working with prefixes easier, especially IP prefixes (IPv4
and IPv6).

`Pfx` defines a prefix as a struct with a number of `bits` and a maximum
`maxlen` length.  Hence a `Pfx` struct represents some domain-specific value,
like an IPv4/6 address or network, a MAC address, a MAC OUI range or something
completely different.

A `Pfx` struct can be created with `Pfx.new/2` using:
- a `t:bitstring/0` and a `t:non_neg_integer/0` for the maximum length,
- a `t:Pfx.t/0` and a `t:non_neg_integer/0` for a (new) maximum length.

This allows for the creation of any sort of prefix.

Use `Pfx.new/1` to create a prefix struct from:
- a `t:Pfx.ip_address/0`,
- a `t:Pfx.ip_prefix/0`, or
- a `t:binary/0`, a string in IPv4 CIDR, IPv6, EUI-48 or EUI-64 format

This creates a IPv4, IPv6, EUI-48 or an EUI-64 prefix.  Other means to create
prefixes include `Pfx.from_mac/1` and `Pfx.from_hex/1`.

Several functions, like `Pfx.unique_local?/1` are more IP oriented, and are
included along with the more generic `Pfx` functions (like `Pfx.cut/3`) in
order to have one module to rule them all.

Functions generally accept either a `t:Pfx.t/0`, a `t:Pfx.ip_address/0`, a
`t:Pfx.ip_prefix/0` or a binary and yield their result in the same fashion:

    iex> hosts("10.10.10.0/30")
    ["10.10.10.0", "10.10.10.1", "10.10.10.2", "10.10.10.3"]

    iex> hosts({{10, 10, 10, 0}, 30})
    [
      {{10, 10, 10, 0}, 32},
      {{10, 10, 10, 1}, 32},
      {{10, 10, 10, 2}, 32},
      {{10, 10, 10, 3}, 32}
    ]

    iex> hosts(%Pfx{bits: <<10, 10, 10, 0::6>>, maxlen: 32})
    [
      %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32},
      %Pfx{bits: <<10, 10, 10, 1>>, maxlen: 32},
      %Pfx{bits: <<10, 10, 10, 2>>, maxlen: 32},
      %Pfx{bits: <<10, 10, 10, 3>>, maxlen: 32},
    ]

    # adopt representation of first argument
    iex> band({10, 10, 10, 1}, "255.255.255.0")
    {10, 10, 10, 0}

    iex> multicast?("ff00::1")
    true

    # MAC OUI prefix
    iex> keep("aa:bb:cc:dd:ee:ff", 24)
    "AA-BB-CC-00-00-00/24"

    # get IPv4 from a IPv4 compatible IPv6 address
    iex> cut("::1.2.3.4", -1, -32)
    "1.2.3.4"

## Validity

The `Pfx.new/2` function will silently clip the provided `bits`-string to
`maxlen`-bits when needed, since a `Pfx` struct named `pfx` is valid, iff:
- `bit_size(pfx.bits)` <= `pfx.maxlen`, and where
- `pfx.maxlen` is a `t:non_neg_integer/0`

Keep that in mind when instantiating directly or updating a `Pfx`, otherwise
functions will choke on it.

Same goes for `t:Pfx.ip_address/0` representations, which must be a valid
`:inet.ip_address()`, representing either an IPv4 or IPv6 address through a
tuple of four `8`-bit wide numbers or eight `16`-bit wide numbers.

If used as the first element in a `t:Pfx.ip_prefix/0` tuple, the second element
is interpreted as the mask, used to clip the bitstring when creating the `Pfx`
struct.  For example: `{{1, 1, 1, 0}, 24}` is the same as `1.1.1.0/24`.  IPv4
masks must be in range `0..32` and IPv6 masks in range `0..128`.  The resulting
`Pfx` will have its `maxlen` set to `32` for IPv4 tuples and `128` for IPv6
tuples.

Last but not least, binaries are interpreted as either an IPv4 in
CIDR-notation, an IPv6 address/prefix, an EUI-48 or EUI-64 formatted string.

    # IPv4
    iex> new("1.2.3.4")
    %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}

    iex> new({1, 2, 3, 4})
    %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}

    iex> new("1.2.3.0/24")
    %Pfx{bits: <<1, 2, 3>>, maxlen: 32}

    iex> new({{1, 2, 3, 0}, 24})
    %Pfx{bits: <<1, 2, 3>>, maxlen: 32}

    # IPv6
    iex> new("acdc:1975::")
    %Pfx{bits: <<0xACDC::16, 0x1975::16, 0::96>>, maxlen: 128}

    iex> new({44252, 6517, 0, 0, 0, 0, 0, 0})
    %Pfx{bits: <<0xACDC::16, 0x1975::16, 0::96>>, maxlen: 128}

    # EUI-48
    iex> new("00-88-88-88-88-88")
    %Pfx{bits: <<0, 0x88, 0x88, 0x88, 0x88, 0x88>>, maxlen: 48}

    iex> new("0088.8888.8888")
    %Pfx{bits: <<0, 0x88, 0x88, 0x88, 0x88, 0x88>>, maxlen: 48}

    # EUI-64
    iex> new("02-88-88-FF-FE-88-88-88")
    %Pfx{bits: <<0x02, 0x88, 0x88, 0xFF, 0xFE, 0x88, 0x88, 0x88>>, maxlen: 64}

    iex> new("0288.88FF.FE88.8888")
    %Pfx{bits: <<0x02, 0x88, 0x88, 0xFF, 0xFE, 0x88, 0x88, 0x88>>, maxlen: 64}

## Ancient tradition

`Pfx.new/1` accepts CIDR-strings which are ultimately processed using erlang's
`:inet.parse_address` which, at the time of writing, still honors the ancient
linux tradition of injecting zero's (rather than appending them) when presented
with less than four IPv4 digits in a CIDR string.

    # "d" -> "0.0.0.d"
    iex> new("10") |> format()
    "0.0.0.10"

    iex> new("10/8") |> format()
    "0.0.0.0/8"

    # "d1.d2" -> "d1.0.0.d2"
    iex> new("10.10") |> format()
    "10.0.0.10"

    iex> new("10.10/16") |> format()
    "10.0.0.0/16"

    # "d1.d2.d3" -> "d1.d2.0.d3"
    iex> new("10.10.10") |> format()
    "10.10.0.10"

    iex> new("10.10.10/24") |> format()
    "10.10.0.0/24"

Bottom line: never go short, you may be unpleasantly surprised.

## EUI-64's

Since a string is first parsed as an IP prefix, EUI-64's like
"11:22:33:44:55:66:77:88" will come out as an IPv6 prefix with their `maxlen`
property set to `128`.  So, when parsing EUI's that might use ':'-s as
punctuation, use `Pfx.from_mac/1`, which also supports the tuple formats.  Like
`Pfx.new/1`, this function always returns a `t:Pfx.t/0`-struct.

    # new/1 parses EUI-64's like these correctly:
    iex> new("1122.3344.5566.7788")
    %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88>>, maxlen: 64}

    iex> new("11-22-33-44-55-66-77-88")
    %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88>>, maxlen: 64}

    # but new/1 turns this valid EUI-64 into IPv6 due to ':'-punctuation used:
    iex> new("01:02:03:04:05:06:07:08")
    %Pfx{bits: <<0x1::16, 0x2::16, 0x3::16, 0x4::16, 0x5::16, 0x6::16, 0x7::16, 0x8::16>>, maxlen: 128}

    # in this case, use from_mac/1
    iex> from_mac("01:02:03:04:05:06:07:08")
    %Pfx{bits: <<0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8>>, maxlen: 64}

    # and supports digit-styled EUI's
    iex> from_mac({0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8})
    %Pfx{bits: <<0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8>>, maxlen: 64}

    # from {{digits}, len}, keeping first 3 bytes
    iex> from_mac({{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}, 24})
    %Pfx{bits: <<0x1, 0x2, 0x3>>, maxlen: 64}


## Enumeration

A `t:Pfx.t/0` implements the `Enumerable` protocol:

    iex> for ip <- %Pfx{bits: <<1, 2, 3, 0::6>>, maxlen: 32}, do: ip
    [
      %Pfx{bits: <<1, 2, 3, 0>>, maxlen: 32},
      %Pfx{bits: <<1, 2, 3, 1>>, maxlen: 32},
      %Pfx{bits: <<1, 2, 3, 2>>, maxlen: 32},
      %Pfx{bits: <<1, 2, 3, 3>>, maxlen: 32},
    ]


## String.Chars

`t:Pfx.t/0` implements the `String.Chars` protocol with some defaults for
prefixes that formats prefixes with:
- `maxlen: 32` as an IPv4 CIDR string,
- `maxlen: 48` as a EUI-48 address string and
- `maxlen: 64` as a EUI-64 address string
- `maxlen: 128` as an IPv6 string

Other `maxlen`'s will simply come out as a series of 8-bit numbers joined by "."
followed by `/num_of_bits`. The latter is omitted if equal to `pfx.bits`
length.

If other formatting is required, use the `Pfx.format/2` function, which takes
some options that help shape the string representation for a `Pfx` struct.

    iex> "#{%Pfx{bits: <<10, 11, 12>>, maxlen: 32}}"
    "10.11.12.0/24"

    iex> "#{new(<<44252::16, 6518::16>>, 128)}"
    "acdc:1976:0:0:0:0:0:0/32"

    iex> "#{%Pfx{bits: <<0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6>>, maxlen: 48}}"
    "A1-B2-C3-D4-E5-F6"

    iex> "#{new(<<1, 2, 3, 4, 5>>, 64)}"
    "01-02-03-04-05-00-00-00/40"

    # the enumeration example earlier, could also read:
    iex> for ip <- new("1.2.3.0/30"), do: "#{ip}"
    [
      "1.2.3.0",
      "1.2.3.1",
      "1.2.3.2",
      "1.2.3.3"
    ]

    # or
    iex> for ip <- new("1.2.3.0/30"), do: digits(ip, 8) |> elem(0)
    [
      {1, 2, 3, 0},
      {1, 2, 3, 1},
      {1, 2, 3, 2},
      {1, 2, 3, 3}
    ]

## Limitations

A lot of `Pfx`-functions convert the `Pfx.bits` bitstring to an integer using
`Pfx.cast/1`, before performing some, often `Bitwise`-related, calculation on
them.  Luckily [Elixir](https://elixir-lang.org/docs.html) can handle pretty
large numbers which seem mostly limited by the available system memory.

Other functions, like `Pfx.digits/2` return a tuple with numbers and are so
limited by the maximum number of elements in a tuple (~16M+).

So if you're taking this somewhere far, far away, heed these limitations before
take off.

Also, everything is done in Elixir with no extra, external dependencies.
Usually fast enough, but if you really feel the need for speed, you might want
to look elsewhere.

Anyway, enough downplay, here are some more examples.

## Examples

    # IANA's OUI range 00-00-5e-xx-xx-xx
    iex> new("00-00-5e-00-00-00/24")
    %Pfx{bits: <<0, 0, 94>>, maxlen: 48}

    # IANA's VRRP MAC address range 00-00-5e-00-01-{VRID}
    iex> vrrp_mac_range = new("00-00-5e-00-01-00/40")
    %Pfx{bits: <<0, 0, 94, 0, 1>>, maxlen: 48}
    iex>
    iex> vrrp_mac = new("00-00-5e-00-01-0f")
    %Pfx{bits: <<0, 0, 94, 0, 1, 15>>, maxlen: 48}
    iex>
    iex> member?(vrrp_mac, vrrp_mac_range)
    true
    iex> cut(vrrp_mac, -1, -8) |> cast()
    15

    iex> new("10.10.10.0/24")
    %Pfx{bits: <<10, 10, 10>>, maxlen: 32}

    iex> mask("10.10.10.0/25")
    "255.255.255.128"

    iex> inv_mask("10.10.10.0/25")
    "0.0.0.127"

    iex> dns_ptr("acdc:1975::b1ba:2021")
    "1.2.0.2.a.b.1.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.7.9.1.c.d.c.a.ip6.arpa"

    iex> teredo_decode("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
    %{
      server: "65.54.227.120",
      client: "192.0.2.45",
      port: 40000,
      flags: {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      prefix: "2001:0000:4136:e378:8000:63bf:3fff:fdd2"
    }

    iex> eui64_encode("0288.8888.8888")
    "00-88-88-FF-FE-88-88-88"

Some functions have IP related names (like `Pfx.teredo_decode/1`, but most of
the times functions have generic names, since they apply to all sorts of
prefixes, e.g.

    iex> partition("10.10.10.0/24", 26)
    [ "10.10.10.0/26",
      "10.10.10.64/26",
      "10.10.10.128/26",
      "10.10.10.192/26"
    ]

    iex> new(<<1, 2, 3, 4>>, 32)
    ...> |> format(width: 1, unit: 8)
    "00000001.00000010.00000011.00000100"

    iex> from_hex("123456789abcdef")
    ...> |> keep(20)
    %Pfx{bits: <<0x12, 0x34, 0x5::4>>, maxlen: 60}

    iex> brot("1.2.3.4", 8)
    "4.1.2.3"

<!-- @MODULEDOC -->

## Installation

[Pfx](https://hexdocs.pm/pfx/Pfx.html) can be installed by adding `pfx` to your
list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:pfx, "~> 0.7.0"}
  ]
end
```

## Copyright and License

Copyright (c) 2021 hertogp

The source code is licensed under the [MIT License](./LICENSE.md).
