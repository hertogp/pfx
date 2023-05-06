alias Pfx

defmodule Alt0 do
  # from known tuple, inline bitstring creation instead of redirecting:
  # that is: def new({a,b,c,d}) does not call new({a,b,c,d},32}) but creates
  # PFx itself. -> about 1.5 times faster.
  defguardp is_8bit(n) when is_integer(n) and -1 < n and n < 256
  defguardp is_ip4len(l) when is_integer(l) and -1 < l and l < 33
  defguardp is_16bit(n) when is_integer(n) and -1 < n and n < 65_536
  defguardp is_ip6len(l) when is_integer(l) and -1 < l and l < 129

  defguardp is_ip4(a, b, c, d, l)
            when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255 and l in 0..32

  # when is_8bit(a) and is_8bit(b) and is_8bit(c) and is_8bit(d) and is_ip4len(l)

  defguardp is_ip6(a, b, c, d, e, f, g, h, l)
            when is_16bit(a) and is_16bit(b) and is_16bit(c) and is_16bit(d) and is_16bit(e) and
                   is_16bit(f) and is_16bit(g) and is_16bit(h) and
                   is_ip6len(l)

  @nat64_lengths [96, 64, 56, 48, 40, 32]
  @errors %{
    :bitpos => "invalid bit position",
    :einval => "expected an ipv4/ipv6 CIDR or EUI-48/64 string",
    :create => "cannot create a Pfx from",
    :ip4dig => "expected valid IPv4 digits",
    :ip4len => "expected a valid IPv4 prefix length",
    :ip6dig => "expected valid IPv6 digits",
    :ip6len => "expected a valid IPv6 prefix length",
    :maxlen => "expected a non_neg_integer for maxlen",
    :nat64 => "expected a valid IPv6 nat64 address",
    :nat64len => "nat64 prefix length not in [#{Enum.join(@nat64_lengths, ", ")}]",
    :nobit => "expected a integer (bit) value 0..1",
    :nobits => "expected a non-empty bitstring",
    :nobitstr => "expected a bitstring",
    :nocapacity => "prefix's capacity exceeded",
    :nocompare => "prefixes have different maxlen's",
    :noeui => "expected an EUI48/64 prefix, string or tuple",
    :noeui64 => "expected an EUI-64 prefix, string or tuple(s)",
    :noflags => "expected a 16-element tuple of bits",
    :nohex => "expected a hexadecimal string",
    :noint => "expected an integer",
    :noints => "expected all integers",
    :noneg => "expected a non_neg_integer",
    :noneighbor => "empty prefixes have no neighbor",
    :nopart => "cannot partition prefixes using",
    :nopos => "expected a pos_integer",
    :noundig => "expected {{n1, n2, ..}, length}",
    :nowidth => "expected valid width",
    :pfx => "expected a valid Pfx struct",
    :pfx4 => "expected a valid IPv4 Pfx",
    :pfx4full => "expected a full IPv4 address",
    :pfx6 => "expected a valid IPv6 Pfx",
    :pfx6full => "expected a full IPv6 address",
    :range => "invalid index range"
  }
  defp arg_error(reason, data) do
    case @errors[reason] do
      nil -> "error #{reason}, #{inspect(data)}"
      msg -> msg <> ", got #{inspect(data)}"
    end
    |> ArgumentError.exception()
  end

  def new({a, b, c, d}) when is_ip4(a, b, c, d, 32) do
    %Pfx{bits: <<a::8, b::8, c::8, d::8>>, maxlen: 32}
  end

  # ipv4 default mask is 32
  def new({{a, b, c, d}, nil}) when is_ip4(a, b, c, d, 32) do
    %Pfx{bits: <<a::8, b::8, c::8, d::8>>, maxlen: 32}
  end

  def new({{a, b, c, d}, len}) when is_ip4(a, b, c, d, len) do
    <<bits::bitstring-size(len), _::bitstring>> = <<a::8, b::8, c::8, d::8>>
    %Pfx{bits: bits, maxlen: 32}
  end

  def new({{a, b, c, d} = digits, len}) when is_ip4(a, b, c, d, 0),
    do: raise(arg_error(:ip4len, {digits, len}))

  def new({{_, _, _, _} = digits, len}),
    do: raise(arg_error(:ip4dig, {digits, len}))

  def new({a, b, c, d, e, f, g, h}) when is_ip6(a, b, c, d, e, f, g, h, 128) do
    %Pfx{bits: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>, maxlen: 128}
  end

  # ipv6 default mask is 128
  def new({{a, b, c, d, e, f, g, h}, nil}) when is_ip6(a, b, c, d, e, f, g, h, 128) do
    %Pfx{bits: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>, maxlen: 128}
  end

  def new({{a, b, c, d, e, f, g, h}, len}) when is_ip6(a, b, c, d, e, f, g, h, len) do
    <<bits::bitstring-size(len), _::bitstring>> =
      <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    %Pfx{bits: bits, maxlen: 128}
  end

  def new({{a, b, c, d, e, f, g, h} = digits, len}) when is_ip6(a, b, c, d, e, f, g, h, 0),
    do: raise(arg_error(:ip6len, {digits, len}))

  def new({{_, _, _, _, _, _, _, _} = digits, len}),
    do: raise(arg_error(:ip6dig, {digits, len}))
end

Alt0.new({10, 10, 10, 10})
|> IO.inspect(label: :alt0)

Pfx.new({10, 10, 10, 10})
|> IO.inspect(label: :pfx)

Alt0.new({0xACDC, 0x1975, 0, 0, 0, 0, 0, 0})
|> IO.inspect(label: :alt0)

Pfx.new({0xACDC, 0x1975, 0, 0, 0, 0, 0, 0})
|> IO.inspect(label: :pfx)

# [[ Compare converting from tuples ]]
# note: Alt0 was adopted by Pfx
# Name                  ips        average  deviation         median         99th %
# Alt0.ip4new        5.12 M      195.31 ns ±15114.83%         151 ns         418 ns
# Pfx.ip4new         4.76 M      210.12 ns ±14707.76%         154 ns         493 ns
#
# Comparison:
# Alt0.ip4new        5.12 M
# Pfx.ip4new         4.76 M - 1.08x slower +14.81 ns
Benchee.run(%{
  "Alt0.ip4new" => fn -> Alt0.new({10, 10, 10, 10}) end,
  "Pfx.ip4new" => fn -> Pfx.new({10, 10, 10, 10}) end
})

# Name                  ips        average  deviation         median         99th %
# Pfx.ip6new         2.78 M      359.15 ns ±14034.71%         255 ns         602 ns
# Alt0.ip6new        2.64 M      378.38 ns ±14746.88%         255 ns         607 ns
#
# Comparison:
# Pfx.ip6new         2.78 M
# Alt0.ip6new        2.64 M - 1.05x slower +19.23 ns
Benchee.run(%{
  "Alt0.ip6new" => fn -> Alt0.new({0xACDC, 0x1975, 0, 0, 0, 0, 0, 0}) end,
  "Pfx.ip6new" => fn -> Pfx.new({0xACDC, 0x1975, 0, 0, 0, 0, 0, 0}) end
})

# [[ Compare different sources with new and from_hex ]]
#
# Name               ips        average  deviation         median         99th %
# tuple        5022.64 K       0.199 μs ±14755.37%       0.154 μs        0.41 μs
# string        804.36 K        1.24 μs  ±4265.11%        0.97 μs        2.32 μs
# from_hex      470.31 K        2.13 μs  ±2235.47%        1.60 μs        4.19 μs
#
# Comparison:
# tuple        5022.64 K
# string        804.36 K - 6.24x slower +1.04 μs
# from_hex      470.31 K - 10.68x slower +1.93 μs
Benchee.run(%{
  "string" => fn -> Pfx.new("10.10.10.10") end,
  "tuple" => fn -> Pfx.new({10, 10, 10, 10}) end,
  "from_hex" => fn -> Pfx.from_hex("10:10:10:10") end
})
