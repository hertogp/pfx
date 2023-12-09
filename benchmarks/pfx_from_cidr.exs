alias Pfx

defmodule Alt0 do
  # convert CIDR string using string decomposition
  def new(str),
    do: newp(str, [], <<>>)

  defp newp(<<c>> <> tail, state, addr) do
    case c do
      d when d in ?0..?9 -> newp(tail, [d - ?0 | state], addr)
      d when d in ?a..?f -> newip6(tail, [10 + d - ?a | state], addr)
      d when d in ?A..?F -> newip6(tail, [10 + d - ?A | state], addr)
      ?. -> newip4(tail, [], ip4(state, addr))
      ?: -> newip6(tail, [], ip6(state, addr))
      ?/ -> mask(tail, %Pfx{bits: ip4(state, addr), maxlen: 32})
    end
  end

  @compile {:inline, ip4: 2}
  def ip4(state, addr) do
    case state do
      [x] -> <<addr::bitstring, x::8>>
      [x, y] -> <<addr::bitstring, y * 10 + x::8>>
      [x, y, z] -> <<addr::bitstring, z * 100 + y * 10 + x::8>>
    end
  end

  @compile {:inline, ip6: 2}
  def ip6(state, addr) do
    case state do
      [w, x, y, z] -> <<addr::bitstring, z::4, y::4, x::4, w::4>>
      [w, x, y] -> <<addr::bitstring, 0::4, y::4, x::4, w::4>>
      [w, x] -> <<addr::bitstring, 0::8, x::4, w::4>>
      [w] -> <<addr::bitstring, w::16>>
      [] -> addr
    end
  end

  def newip4(<<c>> <> tail, state, addr) do
    case c do
      d when d in ?0..?9 -> newip4(tail, [d - ?0 | state], addr)
      ?. -> newip4(tail, [], ip4(state, addr))
      ?/ -> mask(tail, %Pfx{bits: ip4(state, addr), maxlen: 32})
    end
  end

  def newip4(<<>>, state, addr) do
    %Pfx{bits: ip4(state, addr), maxlen: 32}
    |> Pfx.padr()
  end

  def newip6(<<>>, state, addr) do
    %Pfx{bits: ip6(state, addr), maxlen: 128}
    |> Pfx.padr()
  end

  def newip6(<<c>> <> tail, state, addr) do
    case c do
      d when d in ?0..?9 -> newip6(tail, [d - ?0 | state], addr)
      d when d in ?a..?f -> newip6(tail, [10 + d - ?a | state], addr)
      d when d in ?A..?F -> newip6(tail, [10 + d - ?A | state], addr)
      ?: -> newip6(tail, [], ip6(state, addr))
      ?/ -> mask(tail, %Pfx{bits: ip6(state, addr), maxlen: 128})
    end
  end

  def mask(mask, pfx) do
    len =
      case String.to_charlist(mask) do
        [x] -> x - 48
        [x, y] -> 10 * x + y - 528
        [x, y, z] -> x * 100 + 10 * y + z - 5438
      end

    padding = len - bit_size(pfx.bits)

    if padding < 0,
      do: pfx |> Pfx.keep(len),
      else: pfx |> Pfx.padr(0, padding)
  end
end

defmodule Alt1 do
  # Same as Pfx but with different split implementation to get {address, mask}

  def split(<<>>, acc),
    do: {Enum.reverse(acc), nil}

  def split(<<?/>> <> mask, acc) do
    {Enum.reverse(acc), mask(mask, nil)}
  end

  def split(<<d>> <> tail, acc),
    do: split(tail, [d | acc])

  def mask(<<>>, len),
    do: len

  def mask(<<n>> <> tail, nil),
    do: mask(tail, n - ?0)

  def mask(<<n>> <> tail, len),
    do: mask(tail, 10 * len + n - ?0)

  def new(string) when is_binary(string) do
    {address, mask} = split(string, [])

    case :inet_parse.address(address) do
      {:ok, {a, b, c, d}} ->
        mask = mask || 32
        <<bits::bitstring-size(mask), _::bitstring>> = <<a::8, b::8, c::8, d::8>>
        %Pfx{bits: bits, maxlen: 32}

      {:ok, {a, b, c, d, e, f, g, h}} ->
        mask = mask || 128

        <<bits::bitstring-size(mask), _::bitstring>> =
          <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

        %Pfx{bits: bits, maxlen: 128}

      {:error, msg} ->
        raise ArgumentError, inspect(msg)
    end
  rescue
    err -> raise ArgumentError, inspect(err)
  end

  def new(_prefix),
    do: raise(ArgumentError)
end

Alt0.new("10.0.10.10/16")
|> IO.inspect(label: :alt0)

Alt1.new("10.0.10.10/16")
|> IO.inspect(label: :alt1)

Alt0.new("10/16")
|> IO.inspect(label: :alt0)

Alt0.new("10.10.10.10")
|> IO.inspect(label: :alt0)

Pfx.new("10.10.10.10")
|> IO.inspect(label: :pfx)

Alt0.new("acdc:1975::")
|> IO.inspect(label: :alt0)

Alt0.new("acdc:1975:333:444:555:6:7777:8888")
|> IO.inspect(label: :alt0)

Pfx.new("acdc:1975:333:444:555:6:7777:8888")
|> IO.inspect(label: :pfx)

Benchee.run(%{
  "Alt0.ip4new" => fn -> Alt0.new("10.10.10.10/24") end,
  "Alt1.ip4new" => fn -> Alt1.new("10.10.10.10/24") end,
  "Pfx.ip4new" => fn -> Pfx.new("10.10.10.10/24") end
})

Benchee.run(%{
  "Alt0.ip6new" => fn -> Alt0.new("acdc:1975:3333:4444:5555:6666:7777:8888/120") end,
  "Alt1.ip6new" => fn -> Alt1.new("acdc:1975:3333:4444:5555:6666:7777:8888/120") end,
  "Pfx.ip6new" => fn -> Pfx.new("acdc:1975:3333:4444:5555:6666:7777:8888/120") end
})
