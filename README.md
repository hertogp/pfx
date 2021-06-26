# README

![Pfx test](https://github.com/hertogp/pfx/actions/workflows/elixir.yml/badge.svg)

[Online Pfx Documentation](https://hexdocs.pm/pfx).

<!-- @MODULEDOC -->

A `Pfx` represents a sequence of one or more full length addresses.

A prefix is defined by zero or more `bits` & a maximum length `maxlen` and
can be created from:
- a `t:bitstring/0` and a `length`,
- a `t:Pfx.ip_address/0`,
- a {`t:Pfx.ip_address/0`, `length`}-tuple, or
- a `t:binary/0` denoting a prefix in CIDR-notation.

The first option allows for the creation of any sort of prefix, the latter
three yield either an IPv4 of IPv6 prefix.

## Examples

    # An OUI
    iex> new(<<0x00, 0x22, 0x72>>, 48)
    %Pfx{bits: <<0, 34, 114>>, maxlen: 48}

    # IPv4
    iex> new(<<10, 10, 10>>, 32)
    %Pfx{bits: <<10, 10, 10>>, maxlen: 32}

    iex> new({10, 10, 10, 10})
    %Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}

    iex> new({{10, 10, 10, 10}, 24})
    %Pfx{bits: <<10, 10, 10>>, maxlen: 32}

    iex> new("10.10.10.10")
    %Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}

    iex> new("10.10.10.10/24")
    %Pfx{bits: <<10, 10, 10>>, maxlen: 32}

    # IPv6
    iex> new(<<44252::16, 6518::16>>, 128)
    %Pfx{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128}

    iex> new({{44252, 6518, 0, 0, 0, 0, 0, 0}, 32})
    %Pfx{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128}

    iex> new("acdc:1976::/32")
    %Pfx{bits: <<44252::16, 6518::16>>, maxlen: 128}


A `t:Pfx.t/0` is enumerable:

    iex> pfx = new("10.10.10.0/30")
    iex> for ip <- pfx do ip end
    [
      %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32},
      %Pfx{bits: <<10, 10, 10, 1>>, maxlen: 32},
      %Pfx{bits: <<10, 10, 10, 2>>, maxlen: 32},
      %Pfx{bits: <<10, 10, 10, 3>>, maxlen: 32}
    ]

Enumeration yields a list of full-length prefixes.

`t:Pfx.t/0` also implements the `String.Chars` protocol with some defaults for
prefixes that formats:
- `maxlen: 32` as an IPv4 CIDR string,
- `maxlen: 48` as a MAC address string and
- `maxlen: 128` as an IPv6 CIDR string

Other `maxlen`'s will simply come out as a series of 8-bit numbers joined by "."
followed by `/num_of_bits`  If the prefix has `maxlen` bits, the `/num_of_bits`
is omitted.  If the defaults won't yield the desired results, check out the
`Pfx.format/2` function.


## Examples

    iex> "#{new(<<10, 11, 12>>, 32)}"
    "10.11.12.0/24"

    iex> "#{new(<<10, 11, 12, 13>>, 32)}"
    "10.11.12.13"

    iex> "#{new(<<0xACDC::16, 0x1976::16>>, 128)}"
    "ACDC:1976:0:0:0:0:0:0/32"

    iex> "#{new(<<0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6>>, 48)}"
    "A1:B2:C3:D4:E5:F6"

    iex> "#{new(<<1, 2, 3, 4, 5>>, 64)}"
    "1.2.3.4.5.0.0.0/40"


So the list comprehension earlier, could also read:

    iex> prefix = new("10.10.10.0/30")
    iex> for ip <- prefix do "#{ip}" end
    [
      "10.10.10.0",
      "10.10.10.1",
      "10.10.10.2",
      "10.10.10.3"
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

