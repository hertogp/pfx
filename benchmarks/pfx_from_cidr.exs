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
      [w] -> <<addr::bitstring, w::4>>
      [w, x] -> <<addr::bitstring, x::4, w::4>>
      [w, x, y] -> <<addr::bitstring, y::4, x::4, w::4>>
      [w, x, y, z] -> <<addr::bitstring, z::4, y::4, x::4, w::4>>
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

# defmodule Alt1 do
#   # convert CIDR string using charlist
#   def new(str) do
#     str
#     |> String.to_charlist()
#     |> newp([], <<>>)
#   end
#
#   def newp([h | t], state, addr) do
#     case h do
#       ?. -> newip4(t, [], ip4(state, addr))
#       ?: -> newip6(t, [], ip6(state, addr))
#       h when h in ?0..?9 -> newp(t, [h - ?0 | state], addr)
#       h when h in ?a..?f -> newp(t, [10 + h - ?a | state], addr)
#       h when h in ?A..?F -> newp(t, [10 + h - ?A | state], addr)
#     end
#   end
#
#   def newip4([?. | t], state, addr),
#     do: newip4(t, [], ip4(state, addr))
#
#   def newip4([h | t], state, addr),
#     do: newip4(t, [h - ?0 | state], addr)
#
#   def newip4([], state, addr),
#     do: %Pfx{bits: ip4(state, addr), maxlen: 32}
#
#   def newip6([?: | t], state, addr),
#     do: newip6(t, [], ip6(state, addr))
#
#   def newip6([h | t], state, addr) when h in ?0..?9,
#     do: newip6(t, [h - ?0 | state], addr)
#
#   def newip6([h | t], state, addr) when h in ?a..?f,
#     do: newip6(t, [10 + h - ?a | state], addr)
#
#   def newip6([h | t], state, addr) when h in ?A..?F,
#     do: newip6(t, [10 + h - ?A | state], addr)
#
#   def newip6([], state, addr),
#     do: %Pfx{bits: ip6(state, addr), maxlen: 128}
#
#   @compile {:inline, ip4: 2}
#   defp ip4(state, addr) do
#     case state do
#       [x] -> <<addr::bitstring, x::8>>
#       [x, y] -> <<addr::bitstring, x + 10 * y::8>>
#       [x, y, z] -> <<addr::bitstring, x + 10 * y + 100 * z::8>>
#     end
#   end
#
#   @compile {:inline, ip6: 2}
#   defp ip6(state, addr) do
#     case state do
#       [w] -> <<addr::bitstring, w::16>>
#       [w, x] -> <<addr::bitstring, 16 * x + w::16>>
#       [w, x, y] -> <<addr::bitstring, 256 * y + 16 * x + w::16>>
#       [w, x, y, z] -> <<addr::bitstring, 4096 * z + 256 * y + 16 * x + w::16>>
#       [] -> addr
#     end
#   end
# end
#
Alt0.new("10.0.10.10/16")
|> IO.inspect(label: :alt0)

Alt0.new("10/16")
|> IO.inspect(label: :alt0)

Alt0.new("10.10.10.10")
|> IO.inspect(label: :alt0)

# Alt1.new("10.10.10.10")
# |> IO.inspect(label: :alt1)

Pfx.new("10.10.10.10")
|> IO.inspect(label: :pfx)

Alt0.new("acdc:1975::")
|> IO.inspect(label: :alt0)

Pfx.new("acdc:1975:3333:4444:5555:6666:7777:8888")
|> IO.inspect(label: :pfx)

Benchee.run(%{
  "Alt0.ip4new" => fn -> Alt0.new("10.10.10.10/24") end,
  "Pfx.ip4new" => fn -> Pfx.new("10.10.10.10/24") end
})

Benchee.run(%{
  "Alt0.ip6new" => fn -> Alt0.new("acdc:1975:3333:4444:5555:6666:7777:8888/120") end,
  "Pfx.ip6new" => fn -> Pfx.new("acdc:1975:3333:4444:5555:6666:7777:8888/120") end
})
