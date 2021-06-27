defmodule Pfx do
  alias Bitwise

  @external_resource "README.md"

  @moduledoc File.read!("README.md")
             |> String.split("<!-- @MODULEDOC -->")
             |> Enum.fetch!(1)

  @enforce_keys [:bits, :maxlen]
  defstruct bits: <<>>, maxlen: 0

  @typedoc """
  A prefix struct with fields: `bits` and `maxlen`.

  """
  @type t :: %__MODULE__{bits: <<_::_*1>>, maxlen: non_neg_integer}

  @typedoc """
  An :inet IPv4 or IPv6 address (tuple)

  """
  @type ip_address :: :inet.ip4_address() | :inet.ip6_address()

  @typedoc """
  An IPv4 prefix ({`t:inet.ip4_address/0`, 0..32}) or an IPv6 prefix ({`t:inet.ip6_address/0`, 0..128}).

  """
  @type ip_prefix :: {:inet.ip4_address(), 0..32} | {:inet.ip6_address(), 0..128}

  @typedoc """
  A prefix expressed as either a `Pfx`, an address-tuple, an
  address,length-tuple or a CIDR string.

  """
  @type prefix :: t | ip_address | ip_prefix | String.t()

  # valid prefix lengths to use for nat64
  @nat64_lengths [96, 64, 56, 48, 40, 32]

  # Private Guards

  defguardp is_non_neg_integer(n) when is_integer(n) and n >= 0
  defguardp is_pos_integer(n) when is_integer(n) and n > 0
  defguardp is_inrange(x, y, z) when is_integer(x) and y <= x and x <= z

  defguardp is_ip4dig(n) when is_integer(n) and -1 < n and n < 256
  defguardp is_ip4len(l) when is_integer(l) and -1 < l and l < 33
  defguardp is_ip6dig(n) when is_integer(n) and -1 < n and n < 65536
  defguardp is_ip6len(l) when is_integer(l) and -1 < l and l < 129

  defguardp is_ip4(a, b, c, d, l)
            when is_ip4dig(a) and is_ip4dig(b) and is_ip4dig(c) and is_ip4dig(d) and is_ip4len(l)

  defguardp is_ip6(a, b, c, d, e, f, g, h, l)
            when is_ip6dig(a) and is_ip6dig(b) and is_ip6dig(c) and is_ip6dig(d) and is_ip6dig(e) and
                   is_ip6dig(f) and is_ip6dig(g) and is_ip6dig(h) and
                   is_ip6len(l)

  # Guards

  @doc """
  Guard that ensures a given `pfx` is actually valid.
  - it is a `t:Pfx.t/0` struct,
  - `pfx.maxlen` is a `t:non-neg-integer/0`,
  - `pfx.maxlen` is >= 0, and
  - `bit_size(pfx.bits) <= pfx.maxlen`

  """

  defguard is_pfx(pfx)
           when pfx.__struct__ == __MODULE__ and
                  is_non_neg_integer(pfx.maxlen) and
                  bit_size(pfx.bits) <= pfx.maxlen

  @doc """
  Guard that ensures both prefixes are valid and comparable (same maxlen).

  """
  defguard is_comparable(x, y)
           when is_pfx(x) and is_pfx(y) and x.maxlen == y.maxlen

  # Helpers

  defp arg_error(reason, data) do
    msg =
      case reason do
        :bitpos -> "invalid bit position: #{inspect(data)}"
        :cidr -> "expected a valid ipv4/ipv6 CIDR string, got #{inspect(data)}"
        :create -> "cannot create a Pfx from: #{inspect(data)}"
        :ip4dig -> "expected valid IPv4 digits, got #{inspect(data)}"
        :ip4len -> "expected a valid IPv4 prefix length, got #{inspect(data)}"
        :ip6dig -> "expected valid IPv6 digits, got #{inspect(data)}"
        :ip6len -> "expected a valid IPv6 prefix length, got #{inspect(data)}"
        :max -> "expected a non_neg_integer for maxlen, got #{inspect(data)}"
        :nat64 -> "expected a valid IPv6 nat64 address, got #{inspect(data)}"
        :nobit -> "expected a integer (bit) value 0..1, got #{inspect(data)}"
        :nocompare -> "prefixes have different maxlen's: #{inspect(data)}"
        :noint -> "expected an integer, got #{inspect(data)}"
        :noints -> "expected all integers, got #{inspect(data)}"
        :noneg -> "expected a non_neg_integer, got #{inspect(data)}"
        :nopart -> "cannot partition prefixes using #{inspect(data)}"
        :nopos -> "expected a pos_integer, got #{inspect(data)}"
        :nowidth -> "expected valid width, got #{inspect(data)}"
        :pfx -> "expected a valid Pfx struct, got #{inspect(data)}"
        :pfx4 -> "expected a valid IPv4 Pfx, got #{inspect(data)}"
        :pfx6 -> "expected a valid IPv6 Pfx, got #{inspect(data)}"
        :range -> "invalid index range: #{inspect(data)}"
        reason -> "error #{reason}, #{inspect(data)}"
      end

    ArgumentError.exception(msg)
  end

  # optionally drops some lsb's
  defp truncate(bits, max) do
    if bit_size(bits) > max do
      <<part::bitstring-size(max), _::bitstring>> = bits
      part
    else
      bits
    end
  end

  # cast a series of bits to a number, width bits wide.
  # - used for the binary ops on prefixes
  defp castp(bits, width) do
    bsize = bit_size(bits)
    <<x::size(bsize)>> = bits
    Bitwise.bsl(x, width - bsize)
  end

  # split a charlist with length into tuple w/ {'address', length}
  # notes:
  # - ugly code, but a tad faster than multiple func's w/ signatures
  # - crude length "parser":
  #   '1.1.1.1/024' -> {'1.1.1.1', 24}
  defp splitp(charlist, acc) do
    case charlist do
      [?/ | tail] ->
        length =
          case tail do
            [y, z] -> (y - ?0) * 10 + z - ?0
            [z] -> z - ?0
            [x, y, z] -> (x - ?0) * 100 + (y - ?0) * 10 + z - ?0
            _ -> :error
          end

        {Enum.reverse(acc), length}

      [x | tail] ->
        splitp(tail, [x | acc])

      [] ->
        {Enum.reverse(acc), nil}
    end
  end

  # given a valid %Pfx{}=x, turn it into same format as y
  defp marshall(%Pfx{} = x, {_, _, _, _}),
    do: digits(x, 8) |> elem(0)

  defp marshall(%Pfx{} = x, {_, _, _, _, _, _, _, _}),
    do: digits(x, 16) |> elem(0)

  defp marshall(%Pfx{} = x, {{_, _, _, _}, _}),
    do: digits(x, 8)

  defp marshall(%Pfx{} = x, {{_, _, _, _, _, _, _, _}, _}),
    do: digits(x, 16)

  defp marshall(%Pfx{} = x, y) when is_binary(y),
    do: "#{x}"

  defp marshall(%Pfx{} = x, y) when is_pfx(y),
    do: x

  defp marshall(x, y),
    do: raise(arg_error(:marshall, {x, y}))

  # API
  # - new/1 and new/2 *MUST* return a `Pfx` struct or raise an ArgumentError
  #   since many functions use `new` to translate other representations into
  #   a `Pfx` struct and call themselves again.

  @doc """
  Creates a new `t:Pfx.t/0`-prefix.

  A prefix can be created from:
  - from a bitstring and a maximum length, truncating the bits as needed,
  - from a `t:Pfx.t/0` prefix and a new maxlen, again truncating as needed,
  - from an ipv4 or ipv6 `t:ip_address/0` tuple
  - from an {`t:ip_address/0`, `length`} tuple

  The last form sets the `maxlen` according to the IP protocol version used,
  while the `length` parameter is used to truncate the `bits` for the prefix.


  ## Examples

      iex> new(<<10, 10>>, 32)
      %Pfx{bits: <<10, 10>>, maxlen: 32}

      iex> new(<<10, 10>>, 8)
      %Pfx{bits: <<10>>, maxlen: 8}

      # Create a new `Pfx` from an existing one, note:
      # this changes the `Pfx`'s meaning
      iex> new(<<10, 10>>, 32) |> new(128)
      %Pfx{bits: <<10, 10>>, maxlen: 128}

  """
  @spec new(t() | bitstring, non_neg_integer) :: t()
  def new(bits, maxlen) when is_bitstring(bits) and is_non_neg_integer(maxlen),
    do: %__MODULE__{bits: truncate(bits, maxlen), maxlen: maxlen}

  def new(pfx, maxlen) when is_pfx(pfx) and is_non_neg_integer(maxlen),
    do: new(pfx.bits, maxlen)

  def new(x, len) when is_pfx(x),
    do: raise(arg_error(:maxlen, len))

  def new(x, _),
    do: raise(arg_error(:pfx, x))

  @doc """
  Creates a new prefix from address tuples or binaries.

  Use:
  - an ipv4 or ipv6 `t:ip_address/0` tuple directly for a full address, or
  - a {`t:ip_address/0`, `length`}-tuple to truncate the bits to `length`.
  - a binary in
    [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing)-notation,
    like `"acdc:1976::/32"`

  Binaries are processed by `:inet.parse_address/1`, so be aware of IPv4 shorthand
  notations that may yield surprising results, since digits are taken to be:
  - `d1.d2.d3.d4` -> `d1.d2.d3.d4` (full address)
  - `d1.d2.d3` -> `d1.d2.0.d3`
  - `d1.d2` -> `d1.0.0.d2`
  - `d1` -> `0.0.0.d1`

  ## Examples

      iex> new({{0xacdc, 0x1976, 0, 0, 0, 0, 0, 0}, 32})
      %Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128}

      iex> new({10, 10, 0, 0})
      %Pfx{bits: <<10, 10, 0, 0>>, maxlen: 32}

      iex> new({{10, 10, 0, 0}, 16})
      %Pfx{bits: <<10, 10>>, maxlen: 32}

      iex> new("10.10.0.0")
      %Pfx{bits: <<10, 10, 0, 0>>, maxlen: 32}

      iex> new("10.10.10.10/16")
      %Pfx{bits: <<10, 10>>, maxlen: 32}

      # 10.10/16 is interpreted as 10.0.0.10/16 (!)
      iex> new("10.10/16")
      %Pfx{bits: <<10, 0>>, maxlen: 32}


  """
  @spec new(ip_address | ip_prefix | String.t()) :: t()
  def new(prefix)

  # identity
  def new(pfx) when is_pfx(pfx),
    do: pfx

  # ipv4 tuple(s)

  def new({a, b, c, d}),
    do: new({{a, b, c, d}, 32})

  # ipv4 default mask is 32
  def new({{a, b, c, d}, nil}),
    do: new({{a, b, c, d}, 32})

  def new({{a, b, c, d}, len}) when is_ip4(a, b, c, d, len) do
    <<bits::bitstring-size(len), _::bitstring>> = <<a::8, b::8, c::8, d::8>>
    %Pfx{bits: bits, maxlen: 32}
  end

  def new({{a, b, c, d} = digits, len}) when is_ip4(a, b, c, d, 0),
    do: raise(arg_error(:ip4len, {digits, len}))

  def new({{_, _, _, _} = digits, len}),
    do: raise(arg_error(:ip4dig, {digits, len}))

  # ipv6 tuple(s)

  def new({a, b, c, d, e, f, g, h}),
    do: new({{a, b, c, d, e, f, g, h}, 128})

  # ipv6 default mask is 128
  def new({{a, b, c, d, e, f, g, h}, nil}),
    do: new({{a, b, c, d, e, f, g, h}, 128})

  def new({{a, b, c, d, e, f, g, h}, len}) when is_ip6(a, b, c, d, e, f, g, h, len) do
    <<bits::bitstring-size(len), _::bitstring>> =
      <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    %Pfx{bits: bits, maxlen: 128}
  end

  def new({{a, b, c, d, e, f, g, h} = digits, len}) when is_ip6(a, b, c, d, e, f, g, h, 0),
    do: raise(arg_error(:ip6len, {digits, len}))

  def new({{_, _, _, _, _, _, _, _} = digits, len}),
    do: raise(arg_error(:ip6dig, {digits, len}))

  # from ipv4/ipv6 CIDR binary
  def new(string) when is_binary(string) do
    charlist = String.to_charlist(string)
    {address, mask} = splitp(charlist, [])

    try do
      {:ok, digits} = :inet.parse_address(address)
      new({digits, mask})
    rescue
      [MatchError, ArgumentError] -> raise arg_error(:cidr, string)
    end
  end

  def new(prefix),
    do: raise(arg_error(:create, prefix))

  # Bit ops

  @doc """
  Cut out a series of bits and turn it into its own `Pfx`.

  This basically uses `&bits/3` to extract the bits and wraps it in a
  `t:Pfx.t/0` with its `maxlen` set to the length of the bits extracted.

  ## Examples

  As per example on
  [wikipedia](https://en.wikipedia.org/wiki/Teredo_tunneling#IPv6_addressing)
  for an IPv6 address `2001:0000:4136:e378:8000:63bf:3fff:fdd2` that refers to
  a Teredo client:

      iex> teredo = new(<<0x2001::16, 0::16, 0x4136::16, 0xe378::16,
      ...>  0x8000::16, 0x63bf::16, 0x3fff::16, 0xfdd2::16>>, 128)
      iex>
      iex> # client
      iex> cut(teredo, 96, 32) |> bnot() |> format()
      "192.0.2.45"
      iex>
      iex>
      iex> # udp port
      iex> cut(teredo, 80, 16) |> bnot() |> cast()
      40000
      iex>
      iex> # teredo server
      iex> cut(teredo, 32, 32) |> format()
      "65.54.227.120"
      iex>
      iex> # flags
      iex> cut(teredo, 64, 16) |> digits(1) |> elem(0)
      {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

  "Missing" bits are considered to be zero.

      # extract 2nd and 3rd byte:
      iex> %Pfx{bits: <<255, 255>>, maxlen: 32} |> cut(8, 16)
      %Pfx{bits: <<255, 0>>, maxlen: 16}

  Extraction must stay within `maxlen` of given `pfx`.

      # cannot exceed boundaries though:
      iex> %Pfx{bits: <<255, 255>>, maxlen: 32} |> cut(8, 32)
      ** (ArgumentError) invalid index range: {8, 32}

  """
  @spec cut(prefix, integer, integer) :: prefix
  @spec cut(prefix, integer, integer) :: t()
  def cut(pfx, start, length) when is_pfx(pfx) do
    try do
      bits = bits(pfx, start, length)
      new(bits, bit_size(bits))
    rescue
      ArgumentError -> raise arg_error(:range, {start, length})
    end
  end

  def cut(pfx, start, length) do
    IO.inspect(pfx, label: :notanpfx)
    new(pfx) |> cut(start, length) |> marshall(pfx)
  end

  @doc """
  Return `pfx` prefix's bit-value at given `position`.

  A bit position is a `0`-based index from the left with range `0..maxlen-1`.
  A negative bit position is taken relative to `Pfx.maxlen`. A actual bit
  position in the range of `bit_size(pfx.bits)`..`pfx.maxlen - 1` always yields
  `0`.

  ## Examples

      iex> bit(%Pfx{bits: <<1, 2>>, maxlen: 32}, 14)
      1

      iex> bit("1.2.0.0/16", 14)
      1

      iex> bit({1, 2, 0, 0}, 14)
      1

      iex> bit({{1, 2, 0, 0}, 16}, 14)
      1

      # 'missing' bits inside the prefix are deemed to be `0`
      iex> bit("1.2.0.0/16", 24)
      0

      iex> bit("1.2.0.0/16", -8) # same bit, 32 - 8 = 24
      0

      # errors out on invalid positions
      iex> bit("255.255.255.255", 33)
      ** (ArgumentError) invalid bit position: 33

      iex> bit("10.10.0.0/16", -33)
      ** (ArgumentError) invalid bit position: -33

  """
  @spec bit(prefix, integer) :: 0 | 1
  def bit(pfx, position) when position + pfx.maxlen < 0 or position >= pfx.maxlen,
    do: raise(arg_error(:bitpos, position))

  def bit(pfx, position) when is_pfx(pfx) and position < 0,
    do: bit(pfx, pfx.maxlen + position)

  def bit(pfx, pos) when pos < bit_size(pfx.bits) do
    <<_::size(pos), bit::1, _::bitstring>> = pfx.bits
    bit
  end

  def bit(pfx, pos) when pos < pfx.maxlen,
    do: 0

  def bit(pfx, pos),
    do: new(pfx) |> bit(pos)

  @doc """
  Return a series of bits for given `pfx`, starting bit `position` & `length`.

  Negative `position`'s are relative to the end of the `pfx.bits` bitstring,
  while negative `length` will collect bits going left instead of to the
  right.  Note that the bit at given `position` is always included in the
  result regardless of direction.  Finally, a `length` of `0` results in
  an empty bitstring.

  ## Examples

      # first byte
      iex> x = new(<<128, 0, 0, 1>>, 32)
      iex> bits(x, 0, 8)
      <<128>>
      # same as
      iex> bits(x, 7, -8)
      <<128>>

      # last two bytes
      iex> bits("128.0.128.1", 16, 16)
      <<128, 1>>

      iex> bits({128, 0, 128, 1}, 16, 16) # same
      <<128, 1>>

      iex> bits({128, 0, 128, 1}, 31, -16) # same
      <<128, 1>>

      iex> bits({{128, 0, 128, 1}, 32}, 31, -16) # same
      <<128, 1>>

      # missing bits are filled in as `0`
      iex> x = new(<<128>>, 32)
      iex> bits(x, 0, 32)
      <<128, 0, 0, 0>>

      iex> x = new(<<128>>, 32)
      iex> bits(x, 0, 16)
      <<128, 0>>

      iex> x = new(<<128>>, 32)
      iex> bits(x, 15, -16)
      <<128, 0>>

      # the last 5 bits
      iex> x = new(<<255>>, 32)
      iex> bits(x, 7, -5)
      <<0b11111::size(5)>>

  """
  @spec bits(prefix, integer, integer) :: bitstring()
  def bits(pfx, position, length) when is_pfx(pfx) and is_integer(position * length) do
    pos = if position < 0, do: pfx.maxlen + position, else: position
    {pos, len} = if length < 0, do: {pos + 1 + length, -length}, else: {pos, length}

    cond do
      pos < 0 or pos >= pfx.maxlen -> raise arg_error(:range, {position, length})
      pos + len > pfx.maxlen -> raise arg_error(:range, {position, length})
      true -> bitsp(pfx, pos, len)
    end
  end

  def bits(pfx, position, length) when is_pfx(pfx),
    do: raise(arg_error(:range, {position, length}))

  def bits(pfx, position, length),
    do: new(pfx) |> bits(position, length)

  defp bitsp(pfx, pos, len) do
    pfx = padr(pfx)
    <<_::size(pos), bits::bitstring-size(len), _::bitstring>> = pfx.bits
    bits
  end

  @doc """
  Return the concatenation of 1 or more series of bits of the given `pfx`.

  ## Example

      iex> x = new(<<1, 2, 3, 4>>, 32)
      iex> x |> bits([{0,8}, {-1, -8}])
      <<1, 4>>
      #
      iex> x |> bits([{0, 8}, {-1, 8}])
      ** (ArgumentError) invalid index range: {-1, 8}

  """
  @spec bits(t, [{integer, integer}]) :: bitstring
  def bits(pfx, ranges) when is_pfx(pfx) and is_list(ranges) do
    Enum.map(ranges, fn {pos, len} -> bits(pfx, pos, len) end)
    |> Enum.reduce(<<>>, &joinbitsp/2)
  end

  defp joinbitsp(x, y), do: <<y::bitstring, x::bitstring>>

  @doc """
  Cast a `t:prefix/0` to an integer.

  After right padding the given `pfx`, the `pfx.bits` are interpreted as a number
  of `maxlen` bits wide.  Empty prefixes evaluate to `0`, since all 'missing'
  bits are taken to be zero (even if `maxlen` is `0`).

  See `cut/3` for how this capability might be useful.

  ## Examples

      iex> %Pfx{bits: <<255, 255>>, maxlen: 16} |> cast()
      65535

      # missing bits filled in as `0`s
      iex> %Pfx{bits: <<255>>, maxlen: 16} |> cast()
      65280

      iex> %Pfx{bits: <<-1::128>>, maxlen: 128} |> cast()
      340282366920938463463374607431768211455

      iex> %Pfx{bits: <<>>, maxlen: 8} |> cast()
      0

      # a bit weird, but:
      iex> %Pfx{bits: <<>>, maxlen: 0} |> cast()
      0

      iex> %Pfx{bits: <<255, 255, 0, 0>>, maxlen: 32} |> cast()
      4294901760

      iex> cast({255, 255, 0, 0})
      4294901760

      iex> cast({{255, 255, 0, 0}, 32})
      4294901760

      iex> cast("255.255.0.0")
      4294901760

  """
  @spec cast(prefix) :: non_neg_integer
  def cast(pfx) when is_pfx(pfx),
    do: castp(pfx.bits, pfx.maxlen)

  def cast(pfx),
    do: new(pfx) |> cast()

  @doc """
  A bitwise NOT of the `pfx.bits`.

  Results are returned in the same representation as given `pfx`.

  ## Examples

      iex> new(<<255, 255, 0, 0>>, 32) |> bnot()
      %Pfx{bits: <<0, 0, 255, 255>>, maxlen: 32}

      iex> new(<<255, 0>>, 32) |> bnot()
      %Pfx{bits: <<0, 255>>, maxlen: 32}

      iex> bnot("255.255.0.0")
      "0.0.255.255"

      iex> bnot({255, 255, 0, 0})
      {0, 0, 255, 255}

      iex> bnot({{255, 255, 0, 0}, 32})
      {{0, 0, 255, 255}, 32}


  """
  @spec bnot(prefix) :: prefix
  def bnot(pfx) when is_pfx(pfx) do
    width = bit_size(pfx.bits)

    x =
      castp(pfx.bits, width)
      |> Bitwise.bnot()

    %Pfx{pfx | bits: <<x::size(width)>>}
  end

  def bnot(pfx),
    do: new(pfx) |> bnot() |> marshall(pfx)

  @doc """
  A bitwise AND of two `t:prefix/0`'s.

  Both prefixes should, ultimately, have the same `maxlen`.
  If one or more arguments are nog a `Pfx`-struct they are
  are converted using `Pfx.new/1`.

  ## Examples

      iex> x = new(<<128, 129, 130, 131>>, 32)
      iex> y = new(<<255, 255>>, 32)
      iex>
      iex> band(x, y)
      %Pfx{bits: <<128, 129, 0, 0>>, maxlen: 32}
      iex>
      iex> band(y,x)
      %Pfx{bits: <<128, 129, 0, 0>>, maxlen: 32}

      iex> band("1.2.3.4", "255.255.0.0")
      "1.2.0.0"

      iex> band("1.2.3.4", {255, 255, 0, 0})
      "1.2.0.0"

      iex> band({1, 2, 3, 4}, "255.255.0.0")
      {1, 2, 0, 0}

      # both will still have maxlen `32`
      iex> band({{1, 2, 3, 4}, 24}, {{255, 255, 0, 0}, 32})
      {{1, 2, 0, 0}, 32}

      # the work of ancient astrounauts ..
      iex> band("1.2.3.4", "255.255")
      "1.0.0.4"
  """
  @spec band(prefix, prefix) :: prefix
  def band(pfx1, pfx2) when is_comparable(pfx1, pfx2) do
    width = max(bit_size(pfx1.bits), bit_size(pfx2.bits))
    x = castp(pfx1.bits, width)
    y = castp(pfx2.bits, width)
    z = Bitwise.band(x, y)
    %Pfx{pfx1 | bits: <<z::size(width)>>}
  end

  def band(pfx1, pfx2) when is_pfx(pfx1) and is_pfx(pfx2),
    do: raise(arg_error(:nocompare, {pfx1, pfx2}))

  def band(pfx1, pfx2),
    do: band(new(pfx1), new(pfx2)) |> marshall(pfx1)

  @doc """
  A bitwise OR of two prefixes.

  Both prefixes should, ultimately, have the same `maxlen`.
  If one or more arguments are nog a `Pfx`-struct they are
  are converted using `Pfx.new/1`.

  Note that the result is always a full length address whithin given prefix.

  ## Examples

      # same sized `bits`
      iex> x = new(<<10, 11, 12, 13>>, 32)
      iex> y = new(<<0, 0, 255, 255>>, 32)
      iex> bor(x, y)
      %Pfx{bits: <<10, 11, 255, 255>>, maxlen: 32}

      # same `maxlen` but differently sized `bits`: missing bits are considered to be `0`
      iex> x = new(<<10, 11, 12, 13>>, 32)
      iex> y = new(<<255, 255>>, 32)
      iex> bor(x, y)
      %Pfx{bits: <<255, 255, 12, 13>>, maxlen: 32}

      iex> bor("1.2.3.4", "0.0.255.0")
      "1.2.255.4"

      iex> bor({1, 2, 3, 4}, "0.0.255.0")
      {1, 2, 255, 4}

      iex> bor({{1, 2, 3, 4}, 16}, {0, 0, 255, 0})
      {{1, 2, 255, 0}, 32}

  """
  @spec bor(prefix, prefix) :: prefix
  def bor(pfx1, pfx2) when is_comparable(pfx1, pfx2) do
    width = max(bit_size(pfx1.bits), bit_size(pfx2.bits))
    x = castp(pfx1.bits, width)
    y = castp(pfx2.bits, width)
    z = Bitwise.bor(x, y)
    %Pfx{pfx1 | bits: <<z::size(width)>>}
  end

  def bor(pfx1, pfx2) when is_pfx(pfx1) and is_pfx(pfx2),
    do: raise(arg_error(:nocompare, {pfx1, pfx2}))

  def bor(pfx1, pfx2),
    do: bor(new(pfx1), new(pfx2)) |> marshall(pfx1)

  @doc """
  A bitwise XOR of two `t:prefix`'s.

  Both prefixes should, ultimately, have the same `maxlen`.
  If one or more arguments are nog a `Pfx`-struct they are
  are converted using `Pfx.new/1`.

  Note that the result is always a full length address whithin given prefix.

  ## Examples

      iex> x = new(<<10, 11, 12, 13>>, 32)
      iex> y = new(<<255, 255>>, 32)
      iex> bxor(x, y)
      %Pfx{bits: <<245, 244, 12, 13>>, maxlen: 32}

      iex> bxor(%Pfx{bits: <<10, 11, 12, 13>>, maxlen: 32}, "255.255.0.0")
      %Pfx{bits: <<245, 244, 12, 13>>, maxlen: 32}

      iex> bxor("10.11.12.13", {255, 255, 0, 0})
      "245.244.12.13"

      iex> bxor({10, 11, 12, 13}, "255.255.0.0")
      {245, 244, 12, 13}

      iex> bxor({{10, 11, 12, 13}, 32}, "255.255.0.0")
      {{245, 244, 12, 13}, 32}

  """
  @spec bxor(prefix, prefix) :: prefix
  def bxor(pfx1, pfx2) when is_comparable(pfx1, pfx2) do
    width = max(bit_size(pfx1.bits), bit_size(pfx2.bits))
    x = castp(pfx1.bits, width)
    y = castp(pfx2.bits, width)
    z = Bitwise.bxor(x, y)
    %Pfx{pfx1 | bits: <<z::size(width)>>}
  end

  def bxor(pfx1, pfx2) when is_pfx(pfx1) and is_pfx(pfx2),
    do: raise(arg_error(:nocompare, {pfx1, pfx2}))

  def bxor(pfx1, pfx2),
    do: bxor(new(pfx1), new(pfx2)) |> marshall(pfx1)

  @doc """
  Rotate the `pfx.bits` by `n` positions.

  Positive `n` rotates right, negative rotates left.

  Note that the length of the resulting `pfx.bits` stays the same.

  ## Examples

      iex> brot(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}, 8)
      %Pfx{bits: <<4, 1, 2, 3>>, maxlen: 32}

      iex> new(<<1, 2, 3, 4>>, 32) |> brot(-8)
      %Pfx{bits: <<2, 3, 4, 1>>, maxlen: 32}

      iex> brot("1.2.3.4", 8)
      "4.1.2.3"

      iex> brot({1, 2, 3, 4}, 8)
      {4, 1, 2, 3}

      iex> brot({{1, 2, 3, 4}, 32}, -8)
      {{2, 3, 4, 1}, 32}

      # remember, its <<1, 2>> that gets rotated (!)
      iex> brot({{1, 2, 3, 4}, 16}, 8)
      {{2, 1, 0, 0}, 16}


  """
  @spec brot(prefix, integer) :: prefix
  def brot(pfx, n) when is_pfx(pfx) and is_integer(n) and n < 0 do
    plen = bit_size(pfx.bits)
    brot(pfx, plen + rem(n, plen))
  end

  def brot(pfx, n) when is_pfx(pfx) and is_integer(n) do
    width = bit_size(pfx.bits)
    n = rem(n, width)
    x = castp(pfx.bits, width)
    m = Bitwise.bsl(1, n) |> Bitwise.bnot()
    r = Bitwise.band(x, m)
    l = Bitwise.bsr(x, n)
    lw = width - n
    %Pfx{pfx | bits: <<r::size(n), l::size(lw)>>}
  end

  def brot(pfx, n) when is_integer(n),
    do: brot(new(pfx), n) |> marshall(pfx)

  def brot(_, n),
    do: raise(arg_error(:noint, n))

  @doc """
  Arithmetic shift left the `pfx.bits` by `n` positions.

  A positive `n` shifts to the left, negative `n` shifts to the right.
  Note that the length of `pfx.bits` stays the same.

  ## Examples

      iex> bsl(%Pfx{bits: <<1, 2>>, maxlen: 32}, 2)
      %Pfx{bits: <<4, 8>>, maxlen: 32}

      iex> bsl(%Pfx{bits: <<1, 2>>, maxlen: 32}, -2)
      %Pfx{bits: <<0, 64>>, maxlen: 32}

      # mask is applied when creating a `Pfx` out of "1.2.3.4/16"
      iex> bsl("1.2.3.4/16", 2)
      "4.8.0.0/16"

      iex> bsl({1, 2, 3, 4}, 2)
      {4, 8, 12, 16}

      # remember, its <<1, 2>> that gets shifted left 2 bits
      iex> bsl({{1, 2, 3, 4}, 16}, 2)
      {{4, 8, 0, 0}, 16}

  """
  @spec bsl(prefix, integer) :: prefix
  def bsl(pfx, n) when is_pfx(pfx) and is_integer(n) do
    width = bit_size(pfx.bits)

    x =
      castp(pfx.bits, width)
      |> Bitwise.bsl(n)

    %Pfx{pfx | bits: <<x::size(width)>>}
  end

  def bsl(pfx, n) when is_integer(n),
    do: bsl(new(pfx), n) |> marshall(pfx)

  def bsl(_, n),
    do: raise(arg_error(:noint, n))

  @doc """
  Arithmetic shift right the `pfx.bits` by `n` positions.

  A negative `n` actually shifts to the left.
  Note that the `pfx.bits` stays stays the same.

  ## Examples

      iex> bsr(%Pfx{bits: <<1, 2>>, maxlen: 32}, 2)
      %Pfx{bits: <<0, 64>>, maxlen: 32}

      # now shift to the left
      iex> bsr(%Pfx{bits: <<1, 2>>, maxlen: 32}, -2)
      %Pfx{bits: <<4, 8>>, maxlen: 32}

      # mask get applied when creating a `Pfx`
      iex> bsr("1.2.3.4/16", 2)
      "0.64.0.0/16"

      # no mask, so all 32 bits get shifted
      iex> bsr({1, 2, 0, 0}, 2)
      {0, 64, 128, 0}

      iex> bsr({{1, 2, 3, 4}, 16}, 2)
      {{0, 64, 0, 0}, 16}

  """
  @spec bsr(prefix, integer) :: prefix
  def bsr(pfx, n) when is_pfx(pfx) and is_integer(n) do
    width = bit_size(pfx.bits)

    x =
      castp(pfx.bits, width)
      |> Bitwise.bsr(n)

    %Pfx{pfx | bits: <<x::size(width)>>}
  end

  def bsr(pfx, n) when is_integer(n),
    do: bsr(new(pfx), n) |> marshall(pfx)

  def bsr(_, n),
    do: raise(arg_error(:noint, n))

  @doc """
  Right pad the `pfx.bits` to its full length using `0`-bits.

  The result is always a full prefix with `maxlen` bits.

  ## Example

      iex> padr(%Pfx{bits: <<1, 2>>, maxlen: 32})
      %Pfx{bits: <<1, 2, 0, 0>>, maxlen: 32}

      # already a full address
      iex> padr("1.2.0.0")
      "1.2.0.0"

      # mask applied first, then padded with zero's
      iex> padr("1.2.3.4/16")
      "1.2.0.0"

      # mask applied first, than padded with zero's
      iex> padr({{1,2,3,4}, 16})
      {{1, 2, 0, 0}, 32}

  """
  @spec padr(prefix) :: prefix
  def padr(pfx) when is_pfx(pfx),
    do: padr(pfx, 0, pfx.maxlen)

  def padr(pfx),
    do: padr(new(pfx)) |> marshall(pfx)

  @doc """
  Right pad the `pfx.bits` to its full length using either `0` or `1`-bits.

  ## Example

      iex> padr(%Pfx{bits: <<1, 2>>, maxlen: 32}, 1)
      %Pfx{bits: <<1, 2, 255, 255>>, maxlen: 32}

      iex> padr("1.2.0.0/16", 1)
      "1.2.255.255"

      iex> padr({{1, 2, 0, 0}, 16}, 1)
      {{1, 2, 255, 255}, 32}

      # nothing to padr already a full prefix
      iex> padr("1.2.0.0", 1)
      "1.2.0.0"

      iex> padr({1, 2, 0, 0}, 1)
      {1, 2, 0, 0}

  """
  @spec padr(prefix, 0 | 1) :: prefix
  def padr(pfx, bit) when is_pfx(pfx) and (bit === 0 or bit === 1),
    do: padr(pfx, bit, pfx.maxlen)

  def padr(pfx, bit) when bit === 0 or bit === 1,
    do: padr(new(pfx), bit) |> marshall(pfx)

  def padr(_, bit),
    do: raise(arg_error(:nobit, bit))

  @doc """
  Right pad the `pfx.bits` with `n` bits of either `0` or `1`'s.

  The result is clipped at `maxlen` bits without warning.

  ## Examples

      iex> padr(%Pfx{bits: <<255, 255>>, maxlen: 32}, 0, 8)
      %Pfx{bits: <<255, 255, 0>>, maxlen: 32}

      iex> padr(%Pfx{bits: <<255, 255>>, maxlen: 32}, 1, 8)
      %Pfx{bits: <<255, 255, 255>>, maxlen: 32}

      # results are clipped to maxlen
      iex> new(<<1, 2>>, 32) |> padr(0, 512)
      %Pfx{bits: <<1, 2, 0, 0>>, maxlen: 32}

      iex> padr("255.255.0.0/16", 1, 8)
      "255.255.255.0/24"

      iex> padr({{255, 255, 0, 0}, 16}, 1, 8)
      {{255, 255, 255, 0}, 24}

  """
  @spec padr(prefix, 0 | 1, non_neg_integer) :: prefix
  def padr(pfx, bit, n)
      when is_pfx(pfx) and is_integer(n) and n >= 0 and (bit === 0 or bit === 1) do
    bsize = bit_size(pfx.bits)
    nbits = min(n, pfx.maxlen - bsize)
    width = bsize + nbits
    y = if bit == 0, do: 0, else: Bitwise.bsl(1, nbits) - 1
    x = castp(pfx.bits, width) + y

    %Pfx{pfx | bits: <<x::size(width)>>}
  end

  def padr(pfx, bit, n) when is_integer(n) and n >= 0 and (bit === 0 or bit === 1),
    do: padr(new(pfx), bit, n) |> marshall(pfx)

  def padr(_, bit, n) when bit === 0 or bit === 1,
    do: raise(arg_error(:noneg, n))

  def padr(_, bit, _),
    do: raise(arg_error(:nobit, bit))

  @doc """
  Left pad the `pfx.bits` to its full length using `0`-bits.

  ## Example

      iex> padl(%Pfx{bits: <<1, 2>>, maxlen: 32})
      %Pfx{bits: <<0, 0, 1, 2>>, maxlen: 32}

      iex> padl("1.2.0.0/16")
      "0.0.1.2"

      iex> padl({{1, 2, 0, 0}, 16})
      {{0, 0, 1, 2}, 32}

  """
  @spec padl(prefix) :: prefix
  def padl(pfx) when is_pfx(pfx),
    do: padl(pfx, 0, pfx.maxlen)

  def padl(pfx),
    do: padl(new(pfx)) |> marshall(pfx)

  @doc """
  Left pad the `pfx.bits` to its full length using either `0` or `1`-bits.

  ## Example

      iex> padl(%Pfx{bits: <<1, 2>>, maxlen: 32}, 1)
      %Pfx{bits: <<255, 255, 1, 2>>, maxlen: 32}

      iex> padl("1.2.0.0/16", 1)
      "255.255.1.2"

      iex> padl({{1, 2, 0, 0}, 16}, 1)
      {{255, 255, 1, 2}, 32}

  """
  @spec padl(prefix, 0 | 1) :: prefix
  def padl(pfx, bit) when is_pfx(pfx) and (bit === 0 or bit === 1),
    do: padl(pfx, bit, pfx.maxlen)

  def padl(pfx, bit) when bit === 0 or bit === 1,
    do: padl(new(pfx), bit) |> marshall(pfx)

  def padl(_, bit),
    do: raise(arg_error(:nobit, bit))

  @doc """
  Left pad the `pfx.bits` with `n` bits of either `0` or `1`'s.

  ## Example

      iex> padl(%Pfx{bits: <<255, 255>>, maxlen: 32}, 0, 16)
      %Pfx{bits: <<0, 0, 255, 255>>, maxlen: 32}

      iex> padl("255.255.0.0/16", 0, 16)
      "0.0.255.255"

      iex> padl({{255, 255, 0, 0}, 16}, 0, 16)
      {{0, 0, 255, 255}, 32}

  """
  @spec padl(prefix, 0 | 1, non_neg_integer) :: prefix
  def padl(pfx, bit, n)
      when is_pfx(pfx) and is_integer(n) and n >= 0 and (bit === 0 or bit === 1) do
    bsize = bit_size(pfx.bits)
    nbits = min(n, pfx.maxlen - bsize)
    y = if bit == 0, do: 0, else: Bitwise.bsl(1, nbits) - 1
    x = castp(pfx.bits, bsize)

    %Pfx{pfx | bits: <<y::size(nbits), x::size(bsize)>>}
  end

  def padl(pfx, bit, n) when is_integer(n) and n >= 0 and (bit === 0 or bit === 1),
    do: padl(new(pfx), bit, n) |> marshall(pfx)

  def padl(_, bit, n) when bit === 0 or bit === 1,
    do: raise(arg_error(:noneg, n))

  def padl(_, bit, _),
    do: raise(arg_error(:nobit, bit))

  @doc """
  Set all `pfx.bits` to either `0` or `1`.

  ## Examples

      iex> bset(%Pfx{bits: <<1, 1, 1>>, maxlen: 32})
      %Pfx{bits: <<0, 0, 0>>, maxlen: 32}

      iex> bset(%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, 1)
      %Pfx{bits: <<255, 255, 255>>, maxlen: 32}

      # defaults to `0`-bit
      iex> bset("1.1.1.0/24")
      "0.0.0.0/24"

      iex> bset("1.1.1.0/24", 1)
      "255.255.255.0/24"

      iex> bset({{1, 1, 1, 0}, 24}, 1)
      {{255, 255, 255, 0}, 24}


  """
  @spec bset(prefix, 0 | 1) :: prefix
  def bset(pfx, bit \\ 0)

  def bset(pfx, bit) when is_pfx(pfx) and (bit === 0 or bit === 1) do
    bit = if bit == 0, do: 0, else: -1
    len = bit_size(pfx.bits)
    %{pfx | bits: <<bit::size(len)>>}
  end

  def bset(pfx, bit) when bit === 0 or bit === 1,
    do: bset(new(pfx), bit) |> marshall(pfx)

  def bset(_, bit),
    do: raise(arg_error(:nobit, bit))

  # Numbers

  @doc """
  Partition a `Pfx` prefix into a list of new prefixes, each `bitlen` long.

  Note that `bitlen` must be in the range of `bit_size(pfx.bits)..pfx.maxlen-1`.

  ## Examples

      # break out the /26's in a /24
      iex> partition(%Pfx{bits: <<10, 11, 12>>, maxlen: 32}, 26)
      [
        %Pfx{bits: <<10, 11, 12, 0::size(2)>>, maxlen: 32},
        %Pfx{bits: <<10, 11, 12, 1::size(2)>>, maxlen: 32},
        %Pfx{bits: <<10, 11, 12, 2::size(2)>>, maxlen: 32},
        %Pfx{bits: <<10, 11, 12, 3::size(2)>>, maxlen: 32}
      ]

      iex> partition("10.11.12.0/24", 26)
      [
        "10.11.12.0/26",
        "10.11.12.64/26",
        "10.11.12.128/26",
        "10.11.12.192/26"
      ]

      iex> partition({{10, 11, 12, 0}, 24}, 26)
      [
        {{10, 11, 12, 0}, 26},
        {{10, 11, 12, 64}, 26},
        {{10, 11, 12, 128}, 26},
        {{10, 11, 12, 192}, 26},
      ]

  """
  @spec partition(prefix, non_neg_integer) :: list(prefix)
  def partition(pfx, bitlen)
      when is_pfx(pfx) and is_inrange(bitlen, bit_size(pfx.bits), pfx.maxlen) do
    width = bitlen - bit_size(pfx.bits)
    max = Bitwise.bsl(1, width) - 1

    for n <- 0..max do
      %Pfx{pfx | bits: <<pfx.bits::bitstring, n::size(width)>>}
    end
  end

  def partition(pfx, bitlen) when is_pfx(pfx),
    do: arg_error(:nopart, bitlen)

  def partition(pfx, bitlen),
    do: partition(new(pfx), bitlen) |> Enum.map(fn x -> marshall(x, pfx) end)

  @doc """
  Turn a `pfx.bits` string into a list of `{number, width}`-fields.

  If `bit_size(pfx.bits)` is not a multiple of `width`, the last
  `{number, width}`-tuple, will have a smaller width.

  ## Examples

      iex> fields(%Pfx{bits: <<10, 11, 12, 13>>, maxlen: 32}, 8)
      [{10, 8}, {11, 8}, {12, 8}, {13, 8}]

      # not a multiple of 8
      iex> fields(%Pfx{bits: <<10, 11, 12, 0::1>>, maxlen: 32}, 8)
      [{10, 8}, {11, 8}, {12, 8}, {0, 1}]

      iex> new(<<0xacdc::16>>, 128) |> fields(4)
      [{10, 4}, {12, 4}, {13, 4}, {12, 4}]

      iex> fields("10.11.12.13", 8)
      [{10, 8}, {11, 8}, {12, 8}, {13, 8}]

      iex> fields({10, 11, 12, 13}, 8)
      [{10, 8}, {11, 8}, {12, 8}, {13, 8}]

      iex> fields({{10, 11, 12, 0}, 24}, 8)
      [{10, 8}, {11, 8}, {12, 8}]

      # only 1 field with less bits than given width of 64
      iex> new(<<255, 255>>, 32) |> fields(64)
      [{65535, 16}]

  """
  @spec fields(prefix, non_neg_integer) :: list({non_neg_integer, non_neg_integer})
  def fields(pfx, width) when is_pfx(pfx) and is_integer(width) and width > 0,
    do: fields([], pfx.bits, width)

  def fields(pfx, width) when is_integer(width) and width > 0,
    do: fields(new(pfx), width)

  def fields(_, width),
    do: raise(arg_error(:nowidth, width))

  defp fields(acc, <<>>, _width), do: Enum.reverse(acc)

  defp fields(acc, bits, width) when bit_size(bits) >= width do
    <<num::size(width), rest::bitstring>> = bits
    fields([{num, width} | acc], rest, width)
  end

  defp fields(acc, bits, width) do
    w = bit_size(bits)
    <<num::size(w)>> = bits
    fields([{num, w} | acc], "", width)
  end

  @doc """
  Transform a `Pfx` prefix into `{digits, len}` format.

  The `pfx` is padded to its maximum length using `0`'s and the resulting
  bits are grouped into *digits*, each `width`-bits wide.  The resulting `len`
  denotes the original `pfx.bits` bit_size.

  Note: works best if `pfx.maxlen` is a multiple of the `width` used, otherwise
  `maxlen` cannot be inferred from this format by `tuple_size(digits) * width`
  (e.g. by `Pfx.undigits`)

  ## Examples

      iex> digits(%Pfx{bits: <<10, 11, 12>>, maxlen: 32}, 8)
      {{10, 11, 12, 0}, 24}

      # not obvious that each number is 4 bits wide
      iex> digits(%Pfx{bits: <<0x12, 0x34, 0x56, 0x78>>, maxlen: 128}, 4)
      {{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 32}

      iex> digits(%Pfx{bits: <<10, 11, 12, 1::1>>, maxlen: 32}, 8)
      {{10, 11, 12, 128}, 25}

      iex> digits(%Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128}, 16)
      {{44252, 6518, 0, 0, 0, 0, 0, 0}, 32}

      iex> digits("acdc:1976::/32", 16)
      {{44252, 6518, 0, 0, 0, 0, 0, 0}, 32}

      iex> digits({{0xacdc, 0x1976, 0, 0, 0, 0, 0, 0}, 32}, 16)
      {{44252, 6518, 0, 0, 0, 0, 0, 0}, 32}

  """
  @spec digits(prefix, pos_integer) :: {tuple(), pos_integer}
  def digits(pfx, width) when is_pfx(pfx) and is_pos_integer(width) do
    try do
      digits =
        pfx
        |> padr()
        |> fields(width)
        |> Enum.map(fn {n, _w} -> n end)
        |> List.to_tuple()

      {digits, bit_size(pfx.bits)}
    rescue
      _ -> raise arg_error(:digits, {pfx, width})
    end
  end

  def digits(pfx, width) when is_pos_integer(width),
    do: digits(new(pfx), width)

  def digits(_, width),
    do: raise(arg_error(:nowidth, width))

  @doc """
  Return the `Pfx` prefix represented by the `digits`, actual `length` and a given
  field `width`.

  The `pfx.bits` are formed by first concatenating the `digits` expressed as
  bitstrings of `width`-bits wide and then truncating to the `length`-msb bits.

  The `pfx.maxlen` is inferred as `tuple_size(digits) * width`.

  Note: if a digit does not fit in `width`-bits, only the `width`-least
  significant bits are preserved, which may yield surprising results.

  ## Examples

      # truncated to the first 24 bits and maxlen is 32 (4*8)
      iex> undigits({{10, 11, 12, 0}, 24}, 8)
      %Pfx{bits: <<10, 11, 12>>, maxlen: 32}

      iex> undigits({{-1, -1, 0, 0}, 32}, 8) |> format()
      "255.255.0.0"

      # bits are truncated to empty bitstring (`length` is 0)
      iex> undigits({{1,2,3,4}, 0}, 8)
      %Pfx{bits: <<>>, maxlen: 32}

  """
  @spec undigits({tuple(), pos_integer}, pos_integer) :: t
  def undigits({digits, length}, width)
      when is_pos_integer(width) and is_non_neg_integer(length) do
    try do
      bits =
        digits
        |> Tuple.to_list()
        |> Enum.map(fn x -> <<x::size(width)>> end)
        |> Enum.reduce(fn x, acc -> <<acc::bitstring, x::bitstring>> end)
        |> truncate(length)

      Pfx.new(bits, tuple_size(digits) * width)
    rescue
      # in case digits-tuple contains non-integers
      _ -> raise arg_error(:noints, digits)
    end
  end

  def undigits({_digits, length}, width) when is_pos_integer(width),
    do: raise(arg_error(:noneg, length))

  def undigits({_digits, _length}, width),
    do: raise(arg_error(:nopos, width))

  @doc """
  Returns another `Pfx` at distance `offset`.

  This basically increases or decreases the number represented by the `pfx.bits`
  while keeping `pfx.maxlen` the same.

  Note that the length of `pfx.bits` will not change and cycling through
  all siblings will eventually wrap around.

  ## Examples

      # next in line
      iex> sibling(%Pfx{bits: <<10, 11>>, maxlen: 32}, 1)
      %Pfx{bits: <<10, 12>>, maxlen: 32}

      # the last shall be the first
      iex> sibling(%Pfx{bits: <<10, 11, 0>>, maxlen: 32}, 255)
      %Pfx{bits: <<10, 11, 255>>, maxlen: 32}

      iex> sibling(%Pfx{bits: <<10, 11, 0>>, maxlen: 32}, 256)
      %Pfx{bits: <<10, 12, 0>>, maxlen: 32}

      # from one end to another
      iex> new(<<0, 0, 0, 0>>, 32) |> sibling(-1)
      %Pfx{bits: <<255, 255, 255, 255>>, maxlen: 32}

      # zero bit-length stays zero bit-length
      iex> sibling(%Pfx{bits: <<>>, maxlen: 0}, 1)
      %Pfx{bits: <<>>, maxlen: 0}

      iex> sibling("0.0.0.0", -1)
      "255.255.255.255"

      iex> sibling("1.2.3.0/24", -1)
      "1.2.2.0/24"

      iex> sibling({{1, 2, 3, 0}, 24}, 256)
      {{1, 3, 3, 0}, 24}

  """
  @spec sibling(prefix, integer) :: prefix
  def sibling(pfx, offset) when is_pfx(pfx) and is_integer(offset) do
    bsize = bit_size(pfx.bits)
    n = castp(pfx.bits, bit_size(pfx.bits))
    n = n + offset

    %Pfx{pfx | bits: <<n::size(bsize)>>}
  end

  def sibling(pfx, offset) when is_integer(offset),
    do: sibling(new(pfx), offset) |> marshall(pfx)

  def sibling(_, offset),
    do: raise(arg_error(:noint, offset))

  @doc """
  Returns the number of full addresses represented by given `pfx`.

  size(pfx) == 2^(pfx.maxlen - bit_size(pfx.bits))

  ## Examples

      iex> size(%Pfx{bits: <<1, 1, 1>>, maxlen: 32})
      256

      iex> size({{1, 1, 1, 0}, 16})
      65536

      iex> size({1,1,1,1})
      1

      iex> size("1.1.1.0/23")
      512

  """
  @spec size(prefix) :: pos_integer
  def size(pfx) when is_pfx(pfx) do
    :math.pow(2, pfx.maxlen - bit_size(pfx.bits)) |> trunc
  end

  def size(pfx),
    do: size(new(pfx))

  @doc """
  Return the `nth`-member of a given `pfx`.

  A prefix represents a range of (possibly longer) prefixes which can be
  seen as *members* of the prefix.  So a prefix of `n`-bits long represents:
  - 1 prefix of `n`-bits long (i.e. itself),
  - 2 prefixes of `n+1`-bits long,
  - 4 prefixes of `n+2`-bits long
  - ..
  - 2^w prefixes of `n+w`-bits long

  where `n+w` <= `pfx.maxlen`.

  Not specifying a `width` assumes the maximum width available.  If a `width`
  is specified, the `nth`-offset is added to the prefix as a number
  `width`-bits wide.  This wraps around since `<<16::4>>` comes out as
  `<<0::4>>`.

  ## Examples

      iex> member(%Pfx{bits: <<10, 10, 10>>, maxlen: 32}, 0)
      %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32}

      iex> member(%Pfx{bits: <<10, 10, 10>>, maxlen: 32}, 255)
      %Pfx{bits: <<10, 10, 10, 255>>, maxlen: 32}

      # wraps around
      iex> member(%Pfx{bits: <<10, 10, 10>>, maxlen: 32}, 256)
      %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32}

      iex> member(%Pfx{bits: <<10, 10, 10>>, maxlen: 32}, -1)
      %Pfx{bits: <<10, 10, 10, 255>>, maxlen: 32}

      # a full prefix always returns itself
      iex> member(%Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}, 0)
      %Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}

      iex> member(%Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}, 3)
      %Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}

      # other representations work too
      iex> member("10.10.10.0/24", 255)
      "10.10.10.255"

      iex> member("10.10.10.0/24", 256)
      "10.10.10.0"

      iex> member({{10, 10, 10, 0}, 24}, 255)
      {{10, 10, 10, 255}, 32}

  """
  @spec member(prefix, integer) :: prefix
  def member(pfx, nth) when is_pfx(pfx) and is_integer(nth),
    do: member(pfx, nth, pfx.maxlen - bit_size(pfx.bits))

  def member(pfx, nth) when is_integer(nth),
    do: member(new(pfx), nth) |> marshall(pfx)

  def member(_, nth),
    do: raise(arg_error(:noint, nth))

  @doc """
  Return the `nth` subprefix for a given `pfx`, using `width` bits.

  ## Examples

      # the first sub-prefix that is 2 bits longer
      iex> new(<<10, 10, 10>>, 32) |> member(0, 2)
      %Pfx{bits: <<10, 10, 10, 0::2>>, maxlen: 32}

      # the second sub-prefix that is 2 bits longer
      iex> new(<<10, 10, 10>>, 32) |> member(1, 2)
      %Pfx{bits: <<10, 10, 10, 1::2>>, maxlen: 32}

  """
  @spec member(t, integer, pos_integer) :: t
  def member(pfx, nth, width)
      when is_pfx(pfx) and is_integer(nth) and
             is_inrange(width, 0, pfx.maxlen - bit_size(pfx.bits)),
      do: %{pfx | bits: <<pfx.bits::bits, nth::size(width)>>}

  def member(pfx, nth, width) when is_pfx(pfx) and is_integer(nth),
    do: raise(arg_error(:nowidth, width))

  def member(pfx, nth, width)
      when is_pfx(pfx) and is_inrange(width, 0, pfx.maxlen - bit_size(pfx.bits)),
      do: raise(arg_error(:noint, nth))

  def member(pfx, _nth, width) when is_pfx(pfx),
    do: raise(arg_error(:nowidth, width))

  def member(pfx, _, _),
    do: raise(arg_error(:pfx, pfx))

  @doc """
  Returns true is prefix `pfx1` is a member of prefix `pfx2`

  If either `prfx1` or `pfx2` is invalid, member? simply returns false

  """
  @spec member?(t, t) :: boolean
  def member?(pfx1, pfx2)
      when is_comparable(pfx1, pfx2) and bit_size(pfx2.bits) <= bit_size(pfx1.bits),
      do: pfx2.bits == truncate(pfx1.bits, bit_size(pfx2.bits))

  def member?(_, _), do: false

  # Format

  @doc ~S"""
  Generic formatter to turn a `Pfx` into a string, using several options:
  - `:width`, field width (default 8)
  - `:base`, howto turn a field into a string (default 10, use 16 for hex numbers)
  - `:unit`, how many fields go into 1 section (default 1)
  - `:ssep`, howto join the sections together (default ".")
  - `:lsep`, howto join a mask if required (default "/")
  - `:mask`, whether to add a mask (default false)
  - `:reverse`, whether to reverse fields before grouping/joining (default false)
  - `:padding`, whether to pad out the `pfx.bits` (default true)

  The defaults are geared towards IPv4 prefixes, but the options should be able
  to accomodate other domains as well.

  Notes:
  - the *prefix.bits*-length is omitted if equal to the *prefix.bits*-size
  - domain specific submodules probably implement their own formatter.

  ## Examples

      iex> new(<<10, 11, 12>>, 32) |> format()
      "10.11.12.0/24"

      # bitstring, note that mask is applied when new creates the `pfx`
      iex> new("1.2.3.4/24") |> format(width: 1, base: 2, unit: 8, mask: false)
      "00000001.00000010.00000011.00000000"

      # mask not appended as its redundant for a full-sized prefix
      iex> new(<<10, 11, 12, 128>>, 32) |> format()
      "10.11.12.128"

      iex> pfx = new(<<0xacdc::16, 0x1976::16>>, 128)
      iex> format(pfx, width: 16, base: 16, ssep: ":")
      "ACDC:1976:0:0:0:0:0:0/32"
      #
      # similar, but grouping 4 fields, each 4 bits wide, into a single section
      #
      iex> format(pfx, width: 4, base: 16, unit: 4, ssep: ":")
      "ACDC:1976:0000:0000:0000:0000:0000:0000/32"
      #
      # this time, omit the acutal pfx length
      #
      iex> format(pfx, width: 16, base: 16, ssep: ":", mask: false)
      "ACDC:1976:0:0:0:0:0:0"
      #
      # ptr for IPv6 using the nibble format:
      # - dot-separated reversal of all hex digits in the expanded address
      #
      iex> pfx
      ...> |> format(width: 4, base: 16, mask: false, reverse: true)
      ...> |> String.downcase()
      ...> |> (fn x -> "#{x}.ip6.arpa." end).()
      "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.7.9.1.c.d.c.a.ip6.arpa."

      # turn off padding to get reverse zone dns ptr record
      iex> new(<<10, 11, 12>>, 32)
      ...> |> format(padding: false, reverse: true, mask: false)
      ...> |> (&"#{&1}.in-addr.arpa.").()
      "12.11.10.in-addr.arpa."


  """
  @spec format(t, Keyword.t()) :: String.t()
  def format(pfx, opts \\ [])

  def format(pfx, opts) when is_pfx(pfx) do
    width = Keyword.get(opts, :width, 8)
    base = Keyword.get(opts, :base, 10)
    ssep = Keyword.get(opts, :ssep, ".")
    lsep = Keyword.get(opts, :lsep, "/")
    unit = Keyword.get(opts, :unit, 1)
    mask = Keyword.get(opts, :mask, true)
    reverse = Keyword.get(opts, :reverse, false)
    padding = Keyword.get(opts, :padding, true)

    string =
      pfx
      |> (fn x -> if padding, do: padr(x), else: x end).()
      |> fields(width)
      |> Enum.map(fn {n, _w} -> Integer.to_string(n, base) end)
      |> (fn x -> if reverse, do: Enum.reverse(x), else: x end).()
      |> Enum.chunk_every(unit)
      |> Enum.join(ssep)

    if mask and bit_size(pfx.bits) < pfx.maxlen do
      "#{string}#{lsep}#{bit_size(pfx.bits)}"
    else
      string
    end
  end

  def format(pfx, _opts),
    do: raise(arg_error(:pfx, pfx))

  # Sorting

  @doc ~S"""
  Compare function for sorting.

  - `:eq` prefix1 is equal to prefix2
  - `:lt` prefix1 has more bits *or* lies to the left of prefix2
  - `:gt` prefix1 has less bits *or* lies to the right of prefix2

  The prefixes must have the same *maxlen* and are first compared by size
  (i.e. a *shorter* prefix is considered *larger*), and second on their
  bitstring value.

  ## Examples

      iex> compare(new(<<10>>, 32), new(<<11>>, 32))
      :lt

      # sort on `pfx.bits` size first, than on `pfx.bits` values
      iex> l = [new(<<10, 11>>, 32), new(<<10,10,10>>, 32), new(<<10,10>>, 32)]
      iex> Enum.sort(l, Pfx)
      [
        %Pfx{bits: <<10, 10, 10>>, maxlen: 32},
        %Pfx{bits: <<10, 10>>, maxlen: 32},
        %Pfx{bits: <<10, 11>>, maxlen: 32}
      ]
      #
      # whereas regular sort does:
      #
      iex> Enum.sort(l)
      [
        %Pfx{bits: <<10, 10>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10>>, maxlen: 32},
        %Pfx{bits: <<10, 11>>, maxlen: 32}
      ]

      # `pfx1.maxlen` must equal `pfx2.maxlen`
      iex> compare(new(<<10>>, 32), new(<<10>>, 128))
      ** (ArgumentError) prefixes have different maxlen's: {%Pfx{bits: "\n", maxlen: 32}, %Pfx{bits: "\n", maxlen: 128}}

  """
  @spec compare(t, t) :: :eq | :lt | :gt
  def compare(pfx1, pfx2)

  def compare(x, y) when is_comparable(x, y),
    do: comparep(x.bits, y.bits)

  def compare(x, y) when is_pfx(x) and is_pfx(y),
    do: raise(arg_error(:nocompare, {x, y}))

  def compare(x, y) when is_pfx(y),
    do: raise(arg_error(:pfx, x))

  def compare(_x, y),
    do: raise(arg_error(:pfx, y))

  defp comparep(x, y) when bit_size(x) > bit_size(y), do: :lt
  defp comparep(x, y) when bit_size(x) < bit_size(y), do: :gt
  defp comparep(x, y) when x < y, do: :lt
  defp comparep(x, y) when x > y, do: :gt
  defp comparep(x, y) when x == y, do: :eq

  @doc """
  Contrast two `Pfx` prefixes

  Contrasting two prefixes will yield one of:
  - `:equal` pfx1 is equal to pfx2
  - `:more` pfx1 is a more specific version of pfx2
  - `:less` pfx1 is a less specific version of pfx2
  - `:left` pfx1 is left-adjacent to pfx2
  - `:right` pfx1 is right-adjacent to pfx2
  - `:disjoint` pfx1 has no match with pfx2 whatsoever.

  ## Examples

      iex> contrast(new(<<10, 10>>, 32), new(<<10, 10>>, 32))
      :equal

      iex> contrast(new(<<10, 10, 10>>, 32), new(<<10, 10>>, 32))
      :more

      iex> contrast(new(<<10, 10>>, 32), new(<<10, 10, 10>>, 32))
      :less

      iex> contrast(new(<<10, 10>>, 32), new(<<10, 11>>, 32))
      :left

      iex> contrast(new(<<10, 11>>, 32), new(<<10, 10>>, 32))
      :right

      iex> contrast(new(<<10, 10>>, 32), new(<<10, 12>>, 32))
      :disjoint

  """
  @spec contrast(t, t) :: :equal | :more | :less | :left | :right | :disjoint
  def contrast(pfx1, pfx2)

  def contrast(x, y) when is_comparable(x, y),
    do: contrastp(x.bits, y.bits)

  def contrast(x, y) when is_pfx(x) and is_pfx(y),
    do: raise(arg_error(:nocompare, {x, y}))

  def contrast(x, y) when is_pfx(y),
    do: raise(arg_error(:pfx, x))

  def contrast(_, y),
    do: raise(arg_error(:pfx, y))

  defp contrastp(x, y) when x == y,
    do: :equal

  defp contrastp(x, y) when bit_size(x) > bit_size(y),
    do: if(y == truncate(x, bit_size(y)), do: :more, else: :disjoint)

  defp contrastp(x, y) when bit_size(x) < bit_size(y),
    do: if(x == truncate(y, bit_size(x)), do: :less, else: :disjoint)

  defp contrastp(x, y) do
    size = bit_size(x) - 1
    <<n::bitstring-size(size), n1::1>> = x
    <<m::bitstring-size(size), _::1>> = y

    if n == m do
      if n1 == 0, do: :left, else: :right
    else
      :disjoint
    end
  end

  # IP conveniences

  @doc """
  Returns the this-network prefix (full address) for given `pfx`.

  The result is in the same format as `pfx`.

  ## Examples

      iex> network(%Pfx{bits: <<10, 10, 10>>, maxlen: 32})
      %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32}

      # mask is applied to address
      iex> network({{10, 10, 10, 1}, 24})
      {{10, 10, 10, 0}, 32}

      # a full address is its own this-network
      iex> network({10, 10, 10, 1})
      {10, 10, 10, 1}

      iex> network("10.10.10.1/24")
      "10.10.10.0"

      iex> network(%Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128})
      %Pfx{bits: <<0xACDC::16, 0x1976::16, 0::96>>, maxlen: 128}

      iex> network("acdc:1976::/32")
      "ACDC:1976:0:0:0:0:0:0"

  """
  @spec network(prefix) :: prefix
  def network(pfx),
    do: new(pfx) |> padr(0) |> marshall(pfx)

  @doc """
  Returns the broadcast prefix (full address) for given `pfx`.

  The result is in the same format as `pfx`.

  ## Examples

      iex> broadcast(%Pfx{bits: <<10, 10, 10>>, maxlen: 32})
      %Pfx{bits: <<10, 10, 10, 255>>, maxlen: 32}

      iex> broadcast({{10, 10, 10, 1}, 30})
      {{10, 10, 10, 3}, 32}

      # a full address is its own broadcast address
      iex> broadcast({10, 10, 10, 1})
      {10, 10, 10, 1}

      iex> broadcast("10.10.0.0/16")
      "10.10.255.255"

      iex> broadcast(%Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128})
      %Pfx{bits: <<0xACDC::16, 0x1976::16, -1::96>>, maxlen: 128}

  """
  @spec broadcast(t | String.t()) :: t | String.t()
  def broadcast(pfx),
    do: new(pfx) |> padr(1) |> marshall(pfx)

  @doc """
  Returns a list of address prefixes for given `pfx`.

  The result is in the same format as `pfx`.

  ## Examples

      iex> hosts(%Pfx{bits: <<10, 10, 10, 0::6>>, maxlen: 32})
      [
        %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10, 1>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10, 2>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10, 3>>, maxlen: 32}
      ]

      iex> hosts("10.10.10.0/30")
      [
        "10.10.10.0",
        "10.10.10.1",
        "10.10.10.2",
        "10.10.10.3"
      ]

      iex> hosts({{10, 10, 10, 0}, 30})
      [
        {{10, 10, 10, 0}, 32},
        {{10, 10, 10, 1}, 32},
        {{10, 10, 10, 2}, 32},
        {{10, 10, 10, 3}, 32}
      ]

  """
  @spec hosts(t | String.t()) :: list(t) | list(String.t())
  def hosts(pfx),
    do: for(ip <- new(pfx), do: marshall(ip, pfx))

  @doc """
  Return the `nth` host in given `pfx`.

  The result is in the same format as `pfx`.

  Note that offset `nth` wraps around. See `Pfx.member/2`.

  ## Example

      iex> host(%Pfx{bits: <<10, 10, 10>>, maxlen: 32}, 128)
      %Pfx{bits: <<10, 10, 10, 128>>, maxlen: 32}

      iex> host({{10, 10, 10, 0}, 24}, 128)
      {{10, 10, 10, 128}, 32}

      iex> host({10, 10, 10, 10}, 13)
      {10, 10, 10, 10}

      iex> host("10.10.10.0/24", 128)
      "10.10.10.128"

  """
  @spec host(t | String.t(), integer) :: t | String.t()
  def host(pfx, nth) when is_integer(nth),
    do: new(pfx) |> member(nth) |> marshall(pfx)

  def host(_pfx, nth),
    do: raise(arg_error(:noint, nth))

  @doc """
  Return the mask as a `Pfx` for given `pfx`.

  The result is in the same format as `pfx`.

  ## Examples

      iex> mask(%Pfx{bits: <<10, 10, 10, 1::1>>, maxlen: 32})
      %Pfx{bits: <<255, 255, 255, 128>>, maxlen: 32}

      iex> mask({{10, 10, 10, 1}, 25})
      {{255, 255, 255, 128}, 32}

      iex> mask({10, 10, 10, 1})
      {255, 255, 255, 255}

      iex> mask("10.10.10.128/25")
      "255.255.255.128"


  """
  @spec mask(prefix) :: prefix
  def mask(pfx),
    do: new(pfx) |> bset(1) |> padr(0) |> marshall(pfx)

  @doc """
  Returns the inverted mask for given `pfx`.

  The result is in the same format as `pfx`.

  ## Examples

      iex> inv_mask(%Pfx{bits: <<10, 10, 10, 0::1>>, maxlen: 32})
      %Pfx{bits: <<0, 0, 0, 127>>, maxlen: 32}

      iex> inv_mask({{10, 10, 10, 0}, 25})
      {{0, 0, 0, 127}, 32}

      iex> inv_mask({10, 10, 10, 0})
      {0, 0, 0, 0}

      iex> inv_mask("10.10.10.0/25")
      "0.0.0.127"

  """
  @spec inv_mask(prefix) :: prefix
  def inv_mask(pfx),
    do: new(pfx) |> bset(0) |> padr(1) |> marshall(pfx)

  @doc """
  Returns the neighboring prefix such that both can be combined in a supernet.

  The result is in the same format as `pfx`.

  ## Example

      iex> neighbor(%Pfx{bits: <<1, 1, 1, 1::1>>, maxlen: 32})
      %Pfx{bits: <<1, 1, 1, 0::1>>, maxlen: 32}

      iex> neighbor({{1, 1, 1, 128}, 25})
      {{1, 1, 1, 0}, 25}

      iex> neighbor({1, 1, 1, 1})
      {1, 1, 1, 0}

      iex> neighbor("1.1.1.0/25")
      "1.1.1.128/25"

      iex> neighbor("1.1.1.128/25")
      "1.1.1.0/25"

  """
  @spec neighbor(prefix) :: prefix
  def neighbor(pfx) do
    x = new(pfx)
    offset = 1 - 2 * bit(x, bit_size(x.bits) - 1)
    sibling(x, offset) |> marshall(pfx)
  end

  @doc """
  Returns true if *prefix* is a teredo address, false otherwise

  See [rfc4380](https://www.iana.org/go/rfc4380).

  ## Example

      iex> teredo?("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
      true

      iex> teredo?("1.1.1.1")
      false

  """
  @doc section: :ip
  @spec teredo?(prefix) :: boolean
  def teredo?(pfx),
    do: new(pfx) |> member?(%Pfx{bits: <<0x2001::16, 0::16>>, maxlen: 128})

  @doc """
  Returns a map with the teredo address components of `pfx` or nil.

  Returns nil if `pfx` is not a teredo address.

  ## Examples

      # example from https://en.wikipedia.org/wiki/Teredo_tunneling#IPv6_addressing
      iex> teredo("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
      %{
        server: "65.54.227.120",
        client: "192.0.2.45",
        port: 40000,
        flags: {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        prefix: "2001:0000:4136:e378:8000:63bf:3fff:fdd2"
      }

      iex> teredo({0x2001, 0, 0x4136, 0xe378, 0x8000, 0x63bf, 0x3fff, 0xfdd2})
      %{
        server: "65.54.227.120",
        client: "192.0.2.45",
        port: 40000,
        flags: {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        prefix: {0x2001, 0x0, 0x4136, 0xe378, 0x8000, 0x63bf, 0x3fff, 0xfdd2}
      }

      iex> teredo("1.1.1.1")
      nil

  """
  @doc section: :ip
  @spec teredo(prefix) :: map | nil
  def teredo(pfx) do
    # https://www.rfc-editor.org/rfc/rfc4380.html#section-4
    x = new(pfx)

    if teredo?(x) do
      %{
        server: "#{cut(x, 32, 32)}",
        client: "#{cut(x, 96, 32) |> bnot()}",
        port: cut(x, 80, 16) |> bnot() |> cast(),
        flags: cut(x, 64, 16) |> digits(1) |> elem(0),
        prefix: pfx
      }
    else
      nil
    end
  end

  @doc """
  Returns true is `pfx` is a multicast prefix, false otherwise

  ## Examples

      iex> multicast?(%Pfx{bits: <<224, 0, 0, 1>>, maxlen: 32})
      true

      iex> multicast?({{224, 0, 0, 1}, 32})
      true

      iex> multicast?({224, 0, 0, 1})
      true

      iex> multicast?("224.0.0.1")
      true

      iex> multicast?("ff02::1")
      true

      iex> multicast?("1.1.1.1")
      false

  """
  @doc section: :ip
  @spec multicast?(prefix) :: boolean
  def multicast?(pfx) do
    x = new(pfx)

    cond do
      member?(x, %Pfx{bits: <<14::4>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<0xFF>>, maxlen: 128}) -> true
      true -> false
    end
  end

  @doc """
  Returns a map with multicast address components for given `pfx`.

  Returns nil if `pfx` is not a multicast address.

  ## Examples

      iex> multicast(%Pfx{bits: <<0xff02::16, 0::104, 1::8>>, maxlen: 128})
      %{
        preamble: 255,
        flags: {0, 0, 0, 0},
        scope: 2,
        groupID: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
        address: %Pfx{bits: <<0xff02::16, 0::104, 1::8>>, maxlen: 128}
      }

      iex> multicast({0xff02, 0, 0, 0, 0, 0, 0, 1})
      %{
        preamble: 255,
        flags: {0, 0, 0, 0},
        scope: 2,
        groupID: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
        address: {0xff02, 0, 0, 0, 0, 0, 0, 1}
      }

      iex> multicast("ff02::1")
      %{
        preamble: 255,
        flags: {0, 0, 0, 0},
        scope: 2,
        groupID: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
        address: "ff02::1"
      }

  """
  @doc section: :ip
  @spec multicast(prefix) :: map | nil
  def multicast(pfx) do
    x = new(pfx)

    if multicast?(x) do
      case x.maxlen do
        128 ->
          %{
            preamble: cut(x, 0, 8) |> cast(),
            flags: cut(x, 8, 4) |> digits(1) |> elem(0),
            scope: cut(x, 12, 4) |> cast(),
            groupID: bits(x, 16, 112),
            address: pfx
          }

        32 ->
          %{
            digits: digits(x, 8) |> elem(0),
            groupID: bits(x, 4, 28),
            address: marshall(x, pfx)
          }
      end
    else
      nil
    end
  end

  @doc """
  Returns true if `pfx` is a link-local prefix, false otherwise

  Link local prefixes include:

  - `0.0.0.0/8`,          [rfc1122](https://tools.ietf.org/html/rfc1122), this-network (link)
  - `255.255.255.255/32`, [rfc1f22](https://www.iana.org/go/rfc1122), limited broadcast
  - `169.254.0.0/16`,     [rfc3927](https://www.iana.org/go/rfc3927), link-local
  - `fe80::/64`,          [rfc4291](https://tools.ietf.org/html/rfc4291), link-local

  ## Examples

      # first 256 addresses are reserved
      iex> link_local?("169.254.0.0")
      false

      # last 256 addresses are reserved
      iex> link_local?("169.254.255.0")
      false

      # rest is considered link local
      iex> link_local?("169.254.1.0")
      true

      iex> link_local?("169.254.254.255")
      true

      iex> link_local?("0.0.0.0")
      true

      iex> link_local?("0.255.255.255")
      true

      iex> link_local?({0, 255, 255, 255})
      true

      iex> link_local?({{0, 255, 255, 255}, 32})
      true

      iex> link_local?("fe80::acdc:1975")
      true

  """
  @doc section: :ip
  @spec link_local?(prefix) :: boolean
  def link_local?(pfx) do
    # rfc3927 and rfc4271 & friends
    # and https://en.wikipedia.org/wiki/IPv6_address#Default_address_selection
    x = new(pfx)

    cond do
      member?(x, %Pfx{bits: <<169, 254, 0>>, maxlen: 32}) -> false
      member?(x, %Pfx{bits: <<169, 254, 255>>, maxlen: 32}) -> false
      member?(x, %Pfx{bits: <<169, 254>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<0>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<255, 255, 255, 255>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<0xFE80::16, 0::48>>, maxlen: 128}) -> true
      true -> false
    end
  end

  @doc """
  Return a map with link-local address components for given `pfx`.

  Returns nil if `pfx` is not link-local as per
  [rfc3927](https://www.iana.org/go/rfc3927)

  ## Examples

      iex> x = link_local("169.254.128.233")
      iex> x
      %{ digits: {169, 254, 128, 233},
         prefix: "169.254.0.0/16",
         ifaceID: 33001,
         address: "169.254.128.233"
      }
      iex> host(x.prefix, x.ifaceID)
      "169.254.128.233"

      iex> y = link_local("fe80::acdc:1976")
      iex> y
      %{ preamble: 1018,
         prefix: "FE80:0:0:0:0:0:0:0/64",
         ifaceID: 2900105590,
         address: "FE80:0:0:0:0:0:ACDC:1976"
      }
      iex> host(y.prefix, y.ifaceID)
      "FE80:0:0:0:0:0:ACDC:1976"

  """
  @doc section: :ip
  @spec link_local(prefix) :: map | nil
  def link_local(pfx) do
    x = new(pfx)

    if link_local?(x) do
      case x.maxlen do
        128 ->
          %{
            preamble: cut(x, 0, 10) |> cast(),
            prefix: %Pfx{bits: bits(x, 0, 64), maxlen: 128} |> marshall(pfx),
            ifaceID: cut(x, 64, 64) |> cast(),
            address: marshall(x, pfx)
          }

        32 ->
          %{
            digits: digits(x, 8) |> elem(0),
            prefix: %Pfx{bits: bits(x, 0, 16), maxlen: 32} |> marshall(pfx),
            ifaceID: cut(x, 16, 16) |> cast(),
            address: marshall(x, pfx)
          }
      end
    end
  end

  @doc """
  Returns true if `pfx` is designated as "private-use".

  For IPv4 this includes the [rfc1918](https://www.iana.org/go/rfc1918)
  prefixes 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.  For IPv6 this
  includes the [rfc4193](https://www.iana.org/go/rfc4193) prefix fc00::/7.

  ## Examples

      iex> unique_local?(%Pfx{bits: <<172, 31, 255, 255>>, maxlen: 32})
      true

      iex> unique_local?({{172, 31, 255, 255}, 32})
      true

      iex> unique_local?({172, 31, 255, 255})
      true

      iex> unique_local?("172.31.255.255")
      true

      iex> unique_local?("10.10.10.10")
      true

      iex> unique_local?("fc00:acdc::")
      true

      iex> unique_local?("172.32.0.0")
      false

  """
  @doc section: :ip
  @spec unique_local?(prefix) :: boolean
  def unique_local?(pfx) do
    # TODO: what about the well-known nat64 address(es) that are used only
    # locally?
    x = new(pfx)

    cond do
      member?(x, %Pfx{bits: <<10>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<172, 1::4>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<192, 168>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<126::7>>, maxlen: 128}) -> true
      true -> false
    end
  end

  @doc """
  Returns true if `pfx` is matched by the Well-Known Prefixes defined in
  [rfc6053](https://www.iana.org/go/rfc6052) and
  [rfc8215](https://www.iana.org/go/rfc8215), false otherwise.

  Note that organisation specific prefixes might still be used for nat64.

  ## Example

      iex> nat64?(%Pfx{bits: <<0x64::16, 0xff9b::16, 0::64, 0x1010::16, 0x1010::16>>, maxlen: 128})
      true

      iex> nat64?({{0x64, 0xff9b, 0, 0, 0, 0, 0x1010, 0x1010}, 128})
      true

      iex> nat64?({0x64, 0xff9b, 0, 0, 0, 0, 0x1010, 0x1010})
      true

      iex> nat64?("64:ff9b::10.10.10.10")
      true

      iex> nat64?("64:ff9b:1::10.10.10.10")
      true

  """
  @doc section: :ip
  @spec nat64?(prefix) :: boolean
  def nat64?(pfx) do
    x = new(pfx)

    member?(x, %Pfx{bits: <<0x0064::16, 0xFF9B::16, 0::64>>, maxlen: 128}) or
      member?(x, %Pfx{bits: <<0x0064::16, 0xFF9B::16, 1::16>>, maxlen: 128})
  end

  @doc """
  Returns the embedded IPv4 address of a nat64 `pfx`

  The `pfx` prefix should be a full IPv6 address.  The `len` defaults to `96`, but if
  specified it should be one of [#{Enum.join(@nat64_lengths, ", ")}].

  ## Examples

      iex> nat64_decode("64:ff9b::10.10.10.10")
      "10.10.10.10"

      iex> nat64_decode("64:ff9b:1:0a0a:000a:0a00::", 48)
      "10.10.10.10"

      # from rfc6052, section 2.4

      iex> nat64_decode("2001:db8:c000:221::", 32)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:1c0:2:21::", 40)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:c000:2:2100::", 48)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:3c0:0:221::", 56)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:344:c0:2:2100::", 64)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:344::192.0.2.33", 96)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:344::192.0.2.33", 90)
      ** (ArgumentError) error nat64_decode, "len 90 not in: 96, 64, 56, 48, 40, 32"

  """
  @doc section: :ip
  @spec nat64_decode(prefix, integer) :: String.t()
  def nat64_decode(pfx, len \\ 96)

  def nat64_decode(pfx, len) when len in @nat64_lengths do
    x = new(pfx)
    unless bit_size(x.bits) == 128, do: raise(arg_error(:nat64, x))
    x = if len < 96, do: %{x | bits: bits(x, [{0, 64}, {72, 56}])}, else: x
    "#{%Pfx{bits: bits(x, len, 32), maxlen: 32}}"
  end

  def nat64_decode(_, len),
    do: raise(arg_error(:nat64_decode, "len #{len} not in: #{Enum.join(@nat64_lengths, ", ")}"))

  @doc """
  Return an IPv4 embedded IPv6 address for given `pfx6` and `pfx4`.

  The length of the `pfx6.bits` should be one of [#{Enum.join(@nat64_lengths, ", ")}] as defined
  in [rfc6052](https://www.iana.org/go/rfc6052).  The `pfx4` prefix should be a full address.

  ## Examples

      # from rfc6052, section 2.2

      iex> nat64_encode(%Pfx{bits: <<0x2001::16, 0xdb8::16>>, maxlen: 128}, "192.0.2.33")
      %Pfx{bits: <<0x2001::16, 0xdb8::16, 0xc000::16, 0x221::16, 0::64>>, maxlen: 128}

      iex> nat64_encode("2001:db8::/32", "192.0.2.33")
      "2001:DB8:C000:221:0:0:0:0"

      iex> nat64_encode({{0x2001, 0xdb8, 0, 0, 0, 0, 0, 0}, 32}, "192.0.2.33")
      {{0x2001, 0xdb8, 0xc000, 0x221, 0, 0, 0, 0}, 128}

      # other examples
      iex> nat64_encode("2001:db8:100::/40", "192.0.2.33")
      "2001:DB8:1C0:2:21:0:0:0"

      iex> nat64_encode("2001:db8:122::/48", "192.0.2.33")
      "2001:DB8:122:C000:2:2100:0:0"

      iex> nat64_encode("2001:db8:122:300::/56", "192.0.2.33")
      "2001:DB8:122:3C0:0:221:0:0"

      iex> nat64_encode("2001:db8:122:344::/64", "192.0.2.33")
      "2001:DB8:122:344:C0:2:2100:0"

      iex> nat64_encode("2001:db8:122:344::/96", "192.0.2.33")
      "2001:DB8:122:344:0:0:C000:221"

  """
  @doc section: :ip
  @spec nat64_encode(prefix(), prefix()) :: prefix
  def nat64_encode(pfx6, pfx4) do
    ip6 = new(pfx6)

    unless bit_size(ip6.bits) in @nat64_lengths,
      do: raise(arg_error(:nat64, pfx6))

    ip4 = new(pfx4)

    unless bit_size(ip4.bits) == 32,
      do: raise(arg_error(:pfx4, pfx4))

    ip6 = %{ip6 | bits: ip6.bits <> ip4.bits}

    if bit_size(ip6.bits) < 128 do
      %{
        ip6
        | bits:
            <<bits(ip6, [{0, 64}])::bitstring, 0::8,
              bits(ip6, [{64, bit_size(ip6.bits) - 64}])::bitstring>>
      }
      |> padr(0)
      |> marshall(pfx6)
    else
      marshall(ip6, pfx6)
    end
  end

  @doc """
  Return a reverse DNS name (pointer) for given `pfx`.

  The prefix will be padded right with `0`-bits to a multiple of 8 for IPv4 prefixes and
  to a multiple of 4 for IPv6 prefixes.  Note that this might give unexpected results.
  So `dns_ptr/1` works best if the prefix given is actually a multiple of 4 or 8.

  ## Examples

      iex> dns_ptr("10.10.0.0/16")
      "10.10.in-addr.arpa"

      # "1.2.3.0/23" actually encodes as %Pfx{bits: <<1, 2, 1::size(7)>>, maxlen: 32}
      # and padding right with 0-bits to a /24 yields the 1.2.2.0/24 ...
      iex> dns_ptr("1.2.3.0/23")
      "2.2.1.in-addr.arpa"

      iex> dns_ptr("acdc:1976::/32")
      "6.7.9.1.c.d.c.a.ip6.arpa"

      # https://www.youtube.com/watch?v=VD7BV-z5GsE
      iex> dns_ptr("acdc:1975::b1ba:2021")
      "1.2.0.2.a.b.1.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.7.9.1.c.d.c.a.ip6.arpa"

  """
  @doc section: :ip
  @spec dns_ptr(prefix()) :: String.t()
  def dns_ptr(pfx) do
    x = new(pfx)

    {width, base, suffix} =
      case x.maxlen do
        32 -> {8, 10, "in-addr.arpa"}
        128 -> {4, 16, "ip6.arpa"}
        _ -> raise arg_error(:pfx, pfx)
      end

    n = rem(x.maxlen - bit_size(x.bits), width)

    x
    |> padr(0, n)
    |> format(width: width, base: base, padding: false, reverse: true, mask: false)
    |> String.downcase()
    |> (&"#{&1}.#{suffix}").()
  end
end

defimpl String.Chars, for: Pfx do
  def to_string(pfx) do
    case pfx.maxlen do
      32 -> Pfx.format(pfx)
      48 -> Pfx.format(pfx, base: 16, ssep: ":")
      128 -> Pfx.format(pfx, base: 16, width: 16, ssep: ":")
      _ -> Pfx.format(pfx)
    end
  end
end

defimpl Enumerable, for: Pfx do
  require Pfx

  # invalid Pfx yields a count of 0
  def count(pfx),
    do: {:ok, trunc(:math.pow(2, pfx.maxlen - bit_size(pfx.bits)))}

  def member?(x, y) when Pfx.is_comparable(x, y) do
    memberp?(x.bits, y.bits)
  end

  def member?(_, _),
    do: {:ok, false}

  defp memberp?(x, y) when bit_size(x) > bit_size(y),
    do: {:ok, false}

  defp memberp?(x, y) do
    len = bit_size(x)
    <<ypart::bitstring-size(len), _::bitstring>> = y
    {:ok, x == ypart}
  end

  def slice(pfx) do
    {:ok, size} = count(pfx)
    {:ok, size, &slicep(&1, &2)}
  end

  defp slicep(pfx, n) when n < 1,
    do: [Pfx.member(pfx, n)]

  defp slicep(pfx, n),
    do: slicep(pfx, n - 1) ++ [Pfx.member(pfx, n)]

  def reduce(pfx, acc, fun),
    do: reduce(pfx, acc, fun, _idx = 0, _max = Pfx.size(pfx))

  defp reduce(_pfx, {:halt, acc}, _fun, _idx, _max),
    do: {:halted, acc}

  defp reduce(pfx, {:suspend, acc}, fun, idx, max),
    do: {:suspended, acc, &reduce(pfx, &1, fun, idx, max)}

  defp reduce(pfx, {:cont, acc}, fun, idx, max) when idx < max,
    do: reduce(pfx, fun.(Pfx.member(pfx, idx), acc), fun, idx + 1, max)

  defp reduce(_pfx, {:cont, acc}, _fun, _idx, _max),
    do: {:done, acc}
end
