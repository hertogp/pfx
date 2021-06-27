# README

![Pfx test](https://github.com/hertogp/pfx/actions/workflows/elixir.yml/badge.svg)

[Online Pfx Documentation](https://hexdocs.pm/pfx).

<!-- @MODULEDOC -->

Functions to make working with prefixes easier.

`Pfx` defines a prefix as a struct with a number of `bits` and a maximum
`maxlen` length.  Hence a `Pfx` struct represents some domain-specific value,
like an IPv4/6 address or network, a MAC address, a MAC OUI range or something
else entirely.

A `Pfx` struct can be created from:
1. a `t:bitstring/0` and a `t:non_neg_integer/0` for the maximum length,
2. a `t:Pfx.ip_address/0`,
3. a `t:Pfx.ip_prefix/0`, or
4. a `t:binary/0` denoting an IP prefix in CIDR-notation.

The first option allows for the creation of any sort of prefix, the latter
three yield either an IPv4 or IPv6 prefix.

Several functions, like `Pfx.unique_local?/1` are more IP oriented, and are
included along with the more generic `Pfx` functions (like `Pfx.cut/3`) in
order to have one module to rule them all.


## Validity

The `Pfx.new/2` function will silently clip the provided `bits`-string to
`maxlen`-bits when needed, since a `Pfx` struct named `pfx` is valid, iff:
- `bit_size(pfx.bits)` is in range `0..pfx.maxlen-1`, and where
- `pfx.maxlen` is a `t:non_neg_integer/0`

Keep that in mind when instantiating directly or updating a `Pfx`, otherwise
functions will choke on it.

Same goes for `t:Pfx.ip_address/0` representations, which must be a valid
`:inet.ip_address()`, representing either an IPv4 or IPv6 address through a
tuple of four `8`-bit wide numbers or eight `16`-bit wide numbers.

If used as the first element in a `t:Pfx.ip_prefix/0` tuple, the second element
is interpreted as the mask, used to clip the bitstring when creating the `Pfx`
struct.  IPv4 masks must be in range `0..32` and IPv6 masks in range `0..128`.
The resulting `Pfx` will have its `maxlen` set to `32` for IPv4 tuples and
`128` for IPv6 tuples.

Last but not least, a binary is interpreted as a string in CIDR-notation for
some IPv4/IPv6 address or prefix.


## Ancient tradition

`Pfx.new/1` accepts CIDR-strings which are ultimately processed using erlang's
`:inet.parse_address` which, at the time of writing, still honors the ancient
linux tradition of injecting zero's when presented with less than four IPv4
digits in a CIDR string.

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


## Limitations

A lot of `Pfx`-functions convert the `Pfx.bits` bitstring to an integer using
`Pfx.cast/1`, before performing some, often `Bitwise`-related, calculation on
them.  Luckily [Elixir](https://elixir-lang.org/docs.html) can handle pretty
large numbers which seem mostly limited by the available system memory.

Other functions, like `Pfx.digits/2` return a tuple with numbers and are so
limited by the maximum number of elements in a tuple (~16M+).

So if you're taking this somewhere far, far away, heed these limitations before
leaving.

Also, everything is done in Elixir with no extra, external dependencies.
Usually fast enough, but if you really feel the need for speed, you might want
to look elsewhere.

Ayway, enough downplay, here are some examples.

## Examples

    # IANA's OUI range 00-00-5e-xx-xx-xx
    iex> new(<<0x00, 0x00, 0x5e>>, 48)
    %Pfx{bits: <<0, 0, 94>>, maxlen: 48}

    # IANA's assignment for the VRRP MAC address range 00-00-5e-00-01-{VRID}
    iex> vrrp_mac_range = new(<<0x00, 0x00, 0x5e, 0x00, 0x01>>, 48)
    %Pfx{bits: <<0, 0, 94, 0, 1>>, maxlen: 48}
    iex>
    iex> vrrp_mac = new(<<0x00, 0x00, 0x5e, 0x00, 0x01, 0x0f>>, 48)
    %Pfx{bits: <<0, 0, 94, 0, 1, 15>>, maxlen: 48}
    iex>
    iex> member?(vrrp_mac, vrrp_mac_range)
    true
    iex> cut(vrrp_mac, 47, -8) |> cast()
    15

    # IPv4

    iex> new(<<10, 10, 10>>, 32)
    %Pfx{bits: <<10, 10, 10>>, maxlen: 32}

    iex> new("10.10.10.0/24")
    %Pfx{bits: <<10, 10, 10>>, maxlen: 32}

    iex> new({10, 10, 10, 10})
    %Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}

    iex> new({{10, 10, 10, 10}, 24})
    %Pfx{bits: <<10, 10, 10>>, maxlen: 32}

    # IPv6
    iex> new(<<44252::16, 6518::16>>, 128)
    %Pfx{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128}

    iex> new("acdc:1976::/32")
    %Pfx{bits: <<44252::16, 6518::16>>, maxlen: 128}

    iex> new({{44252, 6518, 0, 0, 0, 0, 0, 0}, 32})
    %Pfx{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128}

`t:Pfx.t/0` implements the `String.Chars` protocol with some defaults for
prefixes that formats prefixes with:
- `maxlen: 32` as an IPv4 CIDR string,
- `maxlen: 48` as a MAC address string and
- `maxlen: 128` as an IPv6 CIDR string

Other `maxlen`'s will simply come out as a series of 8-bit numbers joined by "."
followed by `/num_of_bits`. The latter is omitted if equal to `pfx.bits`
length.

If other formatting is required, use the `Pfx.format/2` function, which takes
some options and creates a string representation out of a `Pfx` struct.

    # a subnet
    iex> "#{new(<<10, 11, 12>>, 32)}"
    "10.11.12.0/24"

    # an address
    iex> "#{new(<<10, 11, 12, 13>>, 32)}"
    "10.11.12.13"

    # an ipv6 prefix
    iex> "#{new(<<0xACDC::16, 0x1976::16>>, 128)}"
    "ACDC:1976:0:0:0:0:0:0/32"

    # a MAC address
    iex> "#{new(<<0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6>>, 48)}"
    "A1:B2:C3:D4:E5:F6"

    # just 8-bit numbers and mask length
    iex> "#{new(<<1, 2, 3, 4, 5>>, 64)}"
    "1.2.3.4.5.0.0.0/40"

    # an ip4 address formatted as a string of bits
    iex> new(<<1, 2, 3, 4>>, 32) |> format(width: 1, unit: 8)
    "00000001.00000010.00000011.00000100"


A `t:Pfx.t/0` is also enumerable:

    iex> pfx = new("10.10.10.0/30")
    iex> for ip <- pfx do "#{ip}" end
    [
      "10.10.10.0",
      "10.10.10.1",
      "10.10.10.2",
      "10.10.10.3"
    ]

Functions sometimes have generic names, since they apply to all sorts of
prefixes, e.g.

    iex> pfx = new("10.10.10.0/24")
    iex> partition(pfx, 26) |> Enum.map(fn x -> "#{x}" end)
    [ "10.10.10.0/26",
      "10.10.10.64/26",
      "10.10.10.128/26",
      "10.10.10.192/26"
    ]



<!-- @MODULEDOC -->

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `pfx` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:pfx, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/pfx](https://hexdocs.pm/pfx).

