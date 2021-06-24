defmodule PfxError do
  defexception [:reason, :data]

  @typedoc """
  An exception struct with fields `reason` and `data`.

  PfxError's are raised by Pfx functions when invalid Pfx structs are passed
  in.

  """
  @type t :: %__MODULE__{reason: atom(), data: any()}

  @doc """
  Create a PfxError struct.

  ## Example

      iex> new(:func_x, "1.1.1.256")
      %PfxError{reason: :func_x, data: "1.1.1.256"}

  """
  @spec new(atom(), any()) :: t()
  def new(reason, data),
    do: %__MODULE__{reason: reason, data: data}

  @spec message(t()) :: String.t()
  def message(%__MODULE__{reason: reason, data: data}),
    do: format(reason, data)

  defp format(reason, data), do: "#{reason}: #{inspect(data)}"
end

defmodule Pfx do
  # TODO: still do use or do alias Bitwise and calll the func's rather than the
  # operators like x ^^^ y ?
  use Bitwise
  alias PfxError

  @moduledoc ~S"""
  A `Pfx` represents a sequence of one or more full length addresses.

  A prefix is defined by zero or more `bits` & a maximum length `maxlen`.

      iex> new(<<10, 10, 10>>, 32)
      %Pfx{bits: <<10, 10, 10>>, maxlen: 32}

      iex> new(<<0xacdc::16, 0x1976::16>>, 128)
      %Pfx{bits: <<172, 220, 25, 118>>, maxlen: 128}

      iex> new(<<0xc0, 0x3f, 0xd5>>, 48)
      %Pfx{bits: <<192, 63, 213>>, maxlen: 48}


  The module contains functions to work with prefixes.

  In general, Pfx functions either return some value or a `t:PfxError.t/0` in
  case of any errors.  These exceptions are also passed through if given where
  a prefix was expected.

  A `t:Pfx.t/0` is enumerable:

      iex> pfx = new(<<10,10,10,0::6>>, 32)
      iex> for ip <- pfx do ip end
      [
        %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10, 1>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10, 2>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10, 3>>, maxlen: 32}
      ]

  Enumeration yields a list of full-length prefixes.

  `t:Pfx.t/0` also implements the `String.Chars` protocol with some defaults for
  prefixes that formats maxlen 32 as IPv4, a maxlen of 48 as MAC address and
  a maxlen of 128 as IPv6.  Other maxlen's will simply come out as a series of
  8-bit numbers joined by "." followed by `/num_of_bits`

      iex> "#{new(<<10, 11, 12>>, 32)}"
      "10.11.12.0/24"

      iex> "#{new(<<0xACDC::16, 0x1976::16>>, 128)}"
      "ACDC:1976:0:0:0:0:0:0/32"

      iex> "#{new(<<0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6>>, 48)}"
      "A1:B2:C3:D4:E5:F6"

      iex> "#{new(<<1, 2, 3, 4, 5>>, 64)}"
      "1.2.3.4.5.0.0.0/40"


  So the list comprehension earlier, could also read:

      iex> prefix = new(<<10, 10, 10, 0::6>>, 32)
      iex> for ip <- prefix do "#{ip}" end
      [
        "10.10.10.0",
        "10.10.10.1",
        "10.10.10.2",
        "10.10.10.3"
      ]
  """

  @enforce_keys [:bits, :maxlen]
  defstruct bits: <<>>, maxlen: 0

  @typedoc """
  A prefix struct with fields `bits` and `maxlen`.

  """
  @type t :: %__MODULE__{bits: <<_::_*1>>, maxlen: non_neg_integer}

  # Private Guards

  defguardp is_pfxlen(length) when is_integer(length) and length >= 0
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
  Guard that ensures a given *prefix* is actually valid.
  - it is a `t:Pfx.t/0` struct
  - the length of its *bits* <= *maxlen*


  """

  defguard is_pfx(prefix)
           when prefix.__struct__ == __MODULE__ and
                  bit_size(prefix.bits) <= prefix.maxlen

  @doc """
  Guard that ensures both prefixes are valid and comparable (same maxlen).

  """
  defguard is_comparable(x, y)
           when is_pfx(x) and is_pfx(y) and x.maxlen == y.maxlen

  # Helpers

  @compile inline: [error: 2]
  defp error(reason, data), do: PfxError.new(reason, data)

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
    x <<< (width - bsize)
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

  # API

  @doc """
  Creates a new prefix.

  A prefix can be created from a bitstring and a maximum length, truncating the
  bitstring when needed or from an existing prefix and a new maxlen, again
  truncating the bits when needed.

  ## Examples

      iex> new(<<10, 10>>, 32)
      %Pfx{maxlen: 32, bits: <<10, 10>>}

      iex> new(<<10, 10>>, 8)
      %Pfx{maxlen: 8, bits: <<10>>}

      # changing maxlen changes the prefix' meaning
      iex> new(<<10, 10>>, 32) |> new(128)
      %Pfx{maxlen: 128, bits: <<10, 10>>}

  """
  @spec new(t | bitstring, non_neg_integer) :: t | PfxError.t()
  def new(bits, maxlen) when is_bitstring(bits) and is_pfxlen(maxlen),
    do: %__MODULE__{bits: truncate(bits, maxlen), maxlen: maxlen}

  def new(pfx, maxlen) when is_pfx(pfx) and is_pfxlen(maxlen),
    do: new(pfx.bits, maxlen)

  def new(x, len) when is_pfx(x),
    do: raise(ArgumentError.exception("expected a prefix length integer, got #{inspect(len)}"))

  def new(x, _),
    do: raise(ArgumentError.exception("expected a valid Pfx, got #{inspect(x)}"))

  # IPv4 tuples
  def new({{a, b, c, d}, nil}),
    do: new({{a, b, c, d}, 32})

  def new({{a, b, c, d}, len}) when is_ip4(a, b, c, d, len) do
    <<bits::bitstring-size(len), _::bitstring>> = <<a::8, b::8, c::8, d::8>>
    %Pfx{bits: bits, maxlen: 32}
  end

  def new({a, b, c, d}),
    do: new({{a, b, c, d}, 32})

  # IPv6 tuple(s)
  def new({{a, b, c, d, e, f, g, h}, nil}),
    do: new({{a, b, c, d, e, f, g, h}, 128})

  def new({{a, b, c, d, e, f, g, h}, len}) when is_ip6(a, b, c, d, e, f, g, h, len) do
    <<bits::bitstring-size(len), _::bitstring>> =
      <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

    %Pfx{bits: bits, maxlen: 128}
  end

  def new({a, b, c, d, e, f, g, h}),
    do: new({{a, b, c, d, e, f, g, h}, 128})

  # From Binary
  def new(prefix) when is_binary(prefix) do
    charlist = String.to_charlist(prefix)
    {address, mask} = splitp(charlist, [])

    case {:inet.parse_address(address), mask} do
      {{:error, _}, _} -> error(:new, prefix)
      {_, :error} -> error(:new, prefix)
      {{:ok, digits}, mask} -> new({digits, mask})
    end
  end

  # TODO:
  # - turn IP's encode into new()
  # - turn IP's decode into to_string
  # - raise argument errors when invalid input is passed in
  # - raise PfxError only when encountering an invalid prefix struct
  # - do {:ok, value}, {:error, PfxError} functions too

  # ==========================================================================

  # ==========================================================================
  # Slice-&-Dice

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
      iex> cut(teredo, 96, 32) |> bnot()
      %Pfx{bits: <<192, 0, 2, 45>>, maxlen: 32}
      iex>
      iex> # same as:
      iex> cut(teredo, -1, -32) |> bnot()
      %Pfx{bits: <<192, 0, 2, 45>>, maxlen: 32}
      iex>
      iex> # udp port
      iex> cut(teredo, 80, 16) |> bnot() |> cast()
      40000
      iex>
      iex> # teredo server
      iex> cut(teredo, 32, 32)
      %Pfx{bits: <<65, 54, 227, 120>>, maxlen: 32}
      iex>
      iex> # flags
      iex> cut(teredo, 64, 16) |> digits(1) |> elem(0)
      {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

  "Missing" bits are considered to be zero.

      # extract 2nd and 3rd byte:
      iex> %Pfx{bits: <<255, 255>>, maxlen: 32} |> cut(8, 16)
      %Pfx{bits: <<255, 0>>, maxlen: 16}

  Extraction must stay within `maxlen` of given *prefix*.

      # cannot exceed boundaries though:
      iex> %Pfx{bits: <<255, 255>>, maxlen: 32} |> cut(8, 32)
      %PfxError{reason: :cut,
                    data: {%Pfx{bits: <<255, 255>>, maxlen: 32}, 8, 32}}

  """
  @spec cut(t(), integer, integer) :: t() | PfxError.t()
  def cut(prefix, start, length) when is_pfx(prefix) do
    case bits(prefix, start, length) do
      x when is_exception(x) -> error(:cut, {prefix, start, length})
      bits -> new(bits, bit_size(bits))
    end
  end

  def cut(x, _, _) when is_exception(x), do: x
  def cut(x, p, l), do: error(:cut, {x, p, l})

  # Bit Ops

  @doc """
  Return *prefix*'s bit-value at given *position*.

  A bit position is a `0`-based index from the left.  A position beyond the
  *prefix.bits*-length always yields a `0`, regardless of whether it is also
  beyond *prefix.maxlen*.

  ## Examples

      iex> x = new(<<0, 1>>, 32)
      iex> bit(x, 15)
      1
      iex> bit(x, -17)  # same bit
      1
      iex> bit(x, 12345)
      %PfxError{reason: :bit, data: {%Pfx{bits: <<0, 1>>, maxlen: 32}, 12345}}

  """
  @spec bit(t, integer) :: 0 | 1 | PfxError.t()
  def bit(prefix, position) when position + prefix.maxlen < 0 or position >= prefix.maxlen,
    do: error(:bit, {prefix, position})

  def bit(prefix, position) when position < 0,
    do: bit(prefix, prefix.maxlen + position)

  def bit(prefix, pos) when pos < bit_size(prefix.bits) do
    <<_::size(pos), bit::1, _::bitstring>> = prefix.bits
    bit
  end

  def bit(prefix, pos) when is_pfx(prefix) and pos < prefix.maxlen,
    do: 0

  def bit(x, _) when is_exception(x), do: x
  def bit(x, y), do: error(:bit, {x, y})

  @doc """
  Return a series of bits for given *prefix* and starting bit *position* and
  *length*.

  Negative *position*'s are relative to the end of the prefix's bitstring,
  while negative *length* means collect bits going left instead of to the
  right.  Note that the bit at given *position* is always included in the
  result regardless of direction.

  ## Examples

      iex> x = new(<<128, 0, 0, 1>>, 32)
      iex> # first byte
      iex> x |> bits(0, 8)
      <<128>>
      # same as
      iex> x |> bits(7, -8)
      <<128>>

      # last two bytes
      iex> x = new(<<128, 0, 128, 1>>, 32)
      iex> x |> bits(16, 16)
      <<128, 1>>
      # same as
      iex> x |> bits(-1, -16)
      <<128, 1>>

      # missing bits are filled in as `0`
      iex> x = new(<<128>>, 32)
      iex> x |> bits(0, 32)
      <<128, 0, 0, 0>>
      iex> x |> bits(-1, -32)
      <<128, 0, 0, 0>>

  """
  @spec bits(t, integer, integer) :: bitstring() | PfxError.t()
  def bits(prefix, position, length) when is_pfx(prefix) and is_integer(position * length) do
    pos = if position < 0, do: prefix.maxlen + position, else: position
    {pos, len} = if length < 0, do: {pos + 1 + length, -length}, else: {pos, length}

    cond do
      pos < 0 or pos >= prefix.maxlen -> error(:bits, {prefix, position, length})
      pos + len > prefix.maxlen -> error(:bits, {prefix, position, length})
      true -> bitsp(prefix, pos, len)
    end
  end

  def bits(x, _, _) when is_exception(x), do: x
  def bits(x, p, l), do: error(:bits, {x, p, l})

  defp bitsp(pfx, pos, len) do
    pfx = padr(pfx)
    <<_::size(pos), bits::bitstring-size(len), _::bitstring>> = pfx.bits
    bits
  end

  @doc """
  Return the concatenation of 1 or more snippets of bits of the given *prefix*
  or the first `t:PfxError.t/0` encountered during bit extraction using `bits/3`.

  ## Example

      iex> x = new(<<1, 2, 3, 4>>, 32)
      iex> x |> bits([{0,8}, {-1, -8}])
      <<1, 4>>
      iex> x |> bits([{0, 8}, {-1, 8}])
      %PfxError{reason: :bits, data: {%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}, -1, 8}}

  """
  @spec bits(t, [{integer, integer}]) :: bitstring | PfxError.t()
  def bits(prefix, pos_len) when is_pfx(prefix) and is_list(pos_len) do
    Enum.map(pos_len, fn {pos, len} -> bits(prefix, pos, len) end)
    |> Enum.reduce(<<>>, &joinbitsp/2)
  end

  def bits(x, _) when is_exception(x), do: x
  def bits(x, pl), do: error(:bits, {x, pl})

  # helper to join bits or return any PfxError argument provided
  defp joinbitsp(x, _) when is_exception(x), do: x
  defp joinbitsp(_, y) when is_exception(y), do: y
  defp joinbitsp(x, y), do: <<y::bitstring, x::bitstring>>

  @doc """
  Cast a prefix to an integer.

  After right padding the given *prefix*, the bits are interpreted as a number
  of `maxlen` bits wide.  Empty prefixes evaluate to `0`, since all 'missing'
  bits are taken to be zero (even if `maxlen` is 0-bits).

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

      # bit weird, but:
      iex> %Pfx{bits: <<>>, maxlen: 0} |> cast()
      0

  """
  @spec cast(t()) :: non_neg_integer
  def cast(prefix) when is_pfx(prefix),
    do: castp(prefix.bits, prefix.maxlen)

  def cast(x) when is_exception(x), do: x
  def cast(x), do: error(:cast, x)

  @doc """
  A bitwise NOT of the *prefix.bits*.

  ## Examples

      iex> new(<<255, 255, 0, 0>>, 32) |> bnot()
      %Pfx{bits: <<0, 0, 255, 255>>, maxlen: 32}

      iex> new(<<255, 0>>, 32) |> bnot()
      %Pfx{bits: <<0, 255>>, maxlen: 32}

  """
  @spec bnot(t) :: t | PfxError.t()
  def bnot(prefix) when is_pfx(prefix) do
    width = bit_size(prefix.bits)
    x = castp(prefix.bits, width)
    x = ~~~x
    %Pfx{prefix | bits: <<x::size(width)>>}
  end

  def bnot(x) when is_exception(x), do: x
  def bnot(x), do: error(:bnot, x)

  @doc """
  A bitwise AND of two prefixes.

  ## Examples

      iex> x = new(<<128, 129, 130, 131>>, 32)
      iex> y = new(<<255, 255>>, 32)
      iex>
      iex> band(x, y)
      %Pfx{bits: <<128, 129, 0, 0>>, maxlen: 32}
      iex>
      iex> band(y,x)
      %Pfx{bits: <<128, 129, 0, 0>>, maxlen: 32}

  """
  @spec band(t, t) :: t | PfxError.t()
  def band(prefix1, prefix2) when is_comparable(prefix1, prefix2) do
    width = max(bit_size(prefix1.bits), bit_size(prefix2.bits))
    x = castp(prefix1.bits, width)
    y = castp(prefix2.bits, width)
    z = x &&& y
    %Pfx{prefix1 | bits: <<z::size(width)>>}
  end

  def band(x, _) when is_exception(x), do: x
  def band(_, x) when is_exception(x), do: x
  def band(x, y), do: error(:band, {x, y})

  @doc """
  A bitwise OR of two prefixes.

  ## Examples

      # same size prefixes
      iex> x = new(<<10, 11, 12, 13>>, 32)
      iex> y = new(<<0, 0, 255, 255>>, 32)
      iex> bor(x, y)
      %Pfx{bits: <<10, 11, 255, 255>>, maxlen: 32}

      # different sized prefixes, missing bits are considered to be `0`
      iex> x = new(<<10, 11, 12, 13>>, 32)
      iex> y = new(<<255, 255>>, 32)
      iex> bor(x, y)
      %Pfx{bits: <<255, 255, 12, 13>>, maxlen: 32}
      iex>
      iex> bor(y, x)
      %Pfx{bits: <<255, 255, 12, 13>>, maxlen: 32}


  """
  @spec bor(t, t) :: t | PfxError.t()
  def bor(prefix1, prefix2) when is_comparable(prefix1, prefix2) do
    width = max(bit_size(prefix1.bits), bit_size(prefix2.bits))
    x = castp(prefix1.bits, width)
    y = castp(prefix2.bits, width)
    z = x ||| y
    %Pfx{prefix1 | bits: <<z::size(width)>>}
  end

  def bor(x, _) when is_exception(x), do: x
  def bor(_, x) when is_exception(x), do: x
  def bor(x, y), do: error(:bor, {x, y})

  @doc """
  A bitwise XOR of two prefixes.

  ## Examples

      iex> x = new(<<10, 11, 12, 13>>, 32)
      iex> y = new(<<255, 255, 0, 0>>, 32)
      iex> bxor(x, y)
      %Pfx{bits: <<245, 244, 12, 13>>, maxlen: 32}

      iex> x = new(<<10, 11, 12, 13>>, 32)
      iex> y = new(<<255, 255>>, 32)
      iex> bxor(x, y)
      %Pfx{bits: <<245, 244, 12, 13>>, maxlen: 32}
      iex>
      iex> bxor(y, x)
      %Pfx{bits: <<245, 244, 12, 13>>, maxlen: 32}

  """
  @spec bxor(t, t) :: t | PfxError.t()
  def bxor(prefix1, prefix2) when is_comparable(prefix1, prefix2) do
    width = max(bit_size(prefix1.bits), bit_size(prefix2.bits))
    x = castp(prefix1.bits, width)
    y = castp(prefix2.bits, width)
    z = Bitwise.bxor(x, y)
    # was x ^^^ y
    %Pfx{prefix1 | bits: <<z::size(width)>>}
  end

  def bxor(x, _) when is_exception(x), do: x
  def bxor(_, x) when is_exception(x), do: x
  def bxor(x, y), do: error(:bxor, {x, y})

  @doc """
  Rotate the *prefix.bits* by *n* positions.

  ## Examples

      iex> new(<<1, 2, 3, 4>>, 32) |> brot(8)
      %Pfx{bits: <<4, 1, 2, 3>>, maxlen: 32}

      iex> new(<<1, 2, 3, 4>>, 32) |> brot(-8)
      %Pfx{bits: <<2, 3, 4, 1>>, maxlen: 32}

      iex> new(<<1, 2, 3, 4>>, 32) |> brot(-1)
      %Pfx{bits: <<2, 4, 6, 8>>, maxlen: 32}

  """
  @spec brot(t, integer) :: t | PfxError.t()
  def brot(prefix, n) when is_integer(n) and n < 0 do
    plen = bit_size(prefix.bits)
    brot(prefix, plen + rem(n, plen))
  end

  def brot(prefix, n) when is_pfx(prefix) and is_integer(n) do
    width = bit_size(prefix.bits)
    n = rem(n, width)
    x = castp(prefix.bits, width)
    m = ~~~(1 <<< n)
    r = x &&& m
    l = x >>> n
    lw = width - n
    %Pfx{prefix | bits: <<r::size(n), l::size(lw)>>}
  end

  def brot(x, _) when is_exception(x), do: x
  def brot(_, x) when is_exception(x), do: x
  def brot(x, y), do: error(:brot, {x, y})

  @doc """
  Arithmetic shift left the *prefix.bits* by *n* positions.

  ## Examples

      iex> new(<<1, 2>>, 32) |> bsl(2)
      %Pfx{bits: <<4, 8>>, maxlen: 32}

      iex> new(<<1, 2>>, 32) |> bsl(-2)
      %Pfx{bits: <<0, 64>>, maxlen: 32}

  """
  @spec bsl(t, integer) :: t | PfxError.t()
  def bsl(prefix, n) when is_pfx(prefix) and is_integer(n) do
    width = bit_size(prefix.bits)
    x = castp(prefix.bits, width)
    x = x <<< n
    %Pfx{prefix | bits: <<x::size(width)>>}
  end

  def bsl(x, _) when is_exception(x), do: x
  def bsl(x, y), do: error(:bsl, {x, y})

  @doc """
  Arithmetic shift right the *prefix.bits* by *n* positions.

  ## Examples

      iex> new(<<1, 2>>, 32) |> bsr(2)
      %Pfx{bits: <<0, 64>>, maxlen: 32}

      iex> new(<<1, 2>>, 32) |> bsr(-2)
      %Pfx{bits: <<4, 8>>, maxlen: 32}

  """
  @spec bsr(t, integer) :: t | PfxError.t()
  def bsr(prefix, n) when is_pfx(prefix) and is_integer(n) do
    width = bit_size(prefix.bits)
    x = castp(prefix.bits, width)
    x = x >>> n
    %Pfx{prefix | bits: <<x::size(width)>>}
  end

  def bsr(x, _) when is_exception(x), do: x
  def bsr(x, y), do: error(:bsr, {x, y})

  @doc """
  Right pad the *prefix.bits* to its full length using `0`-bits.

  ## Example

      iex> new(<<1, 2>>, 32) |> padr()
      %Pfx{bits: <<1, 2, 0, 0>>, maxlen: 32}

  """
  @spec padr(t) :: t | PfxError.t()
  def padr(x) when is_pfx(x), do: padr(x, 0, x.maxlen)
  def padr(x) when is_exception(x), do: x
  def padr(x), do: error(:padr, x)

  @doc """
  Right pad the *prefix.bits* to its full length using either `0` or `1`-bits.

  If *bit* is anything other than `0`, `1`-bits are used for padding.

  ## Example

      iex> new(<<1, 2>>, 32) |> padr(1)
      %Pfx{bits: <<1, 2, 255, 255>>, maxlen: 32}

  """
  @spec padr(t, 0 | 1) :: t | PfxError.t()
  def padr(x, bit) when is_pfx(x), do: padr(x, bit, x.maxlen)
  def padr(x, _) when is_exception(x), do: x
  def padr(x, y), do: error(:padr, {x, y})

  @doc """
  Right pad the *prefix.bits* with *n* bits of either `0` or `1`'s.

  If *bit* is anything other than `0`, `1`-bits are used for padding.  The
  result is silently clipped to its maximum length.

  ## Examples

      iex> prefix = new(<<255, 255>>, 32)
      iex> padr(prefix, 0, 8)
      %Pfx{bits: <<255, 255, 0>>, maxlen: 32}
      #
      iex> padr(prefix, 1, 16)
      %Pfx{bits: <<255, 255, 255, 255>>, maxlen: 32}

      # results are clipped to maxlen
      iex> new(<<1, 2>>, 32) |> padr(0, 64)
      %Pfx{bits: <<1, 2, 0, 0>>, maxlen: 32}

  """
  @spec padr(t, 0 | 1, non_neg_integer) :: t | PfxError.t()
  def padr(prefix, bit, n) when is_pfx(prefix) and is_integer(n) do
    bsize = bit_size(prefix.bits)
    nbits = min(n, prefix.maxlen - bsize)
    width = bsize + nbits
    y = if bit == 0, do: 0, else: (1 <<< nbits) - 1
    x = castp(prefix.bits, width) + y

    %Pfx{prefix | bits: <<x::size(width)>>}
  end

  def padr(x, _, _) when is_exception(x), do: x
  def padr(x, b, n), do: error(:padr, {x, b, n})

  @doc """
  Left pad the *prefix.bits* to its full length using `0`-bits.

  ## Example

      iex> new(<<1, 2>>, 32) |> padl()
      %Pfx{bits: <<0, 0, 1, 2>>, maxlen: 32}

  """
  @spec padl(t) :: t | PfxError.t()
  def padl(x) when is_pfx(x), do: padl(x, 0, x.maxlen)
  def padl(x) when is_exception(x), do: x
  def padl(x), do: error(:padl, x)

  @doc """
  Left pad the *prefix.bits* to its full length using either `0` or `1`-bits.

  If *bit* is anything other than `0`, `1`-bits are used for padding.

  ## Example

      iex> new(<<1, 2>>, 32) |> padl(1)
      %Pfx{bits: <<255, 255, 1, 2>>, maxlen: 32}

  """
  @spec padl(t, 0 | 1) :: t | PfxError.t()
  def padl(x, bit) when is_pfx(x), do: padl(x, bit, x.maxlen)
  def padl(x, _) when is_exception(x), do: x
  def padl(x, y), do: error(:padl, {x, y})

  @doc """
  Left pad the *prefix.bits* with *n* bits of either `0` or `1`'s.

  If *bit* is anything other than `0`, `1`-bits are used for padding.  The
  result is silently clipped to its maximum length.

  ## Example

      iex> new(<<>>, 32) |> padl(1, 16) |> padl(0, 16)
      %Pfx{bits: <<0, 0, 255, 255>>, maxlen: 32}

  """
  @spec padl(t, 0 | 1, non_neg_integer) :: t | PfxError.t()
  def padl(prefix, bit, n) when is_pfx(prefix) and is_integer(n) do
    bsize = bit_size(prefix.bits)
    nbits = min(n, prefix.maxlen - bsize)
    y = if bit == 0, do: 0, else: (1 <<< nbits) - 1
    x = castp(prefix.bits, bsize)

    %Pfx{prefix | bits: <<y::size(nbits), x::size(bsize)>>}
  end

  def padl(x, _, _) when is_exception(x), do: x
  def padl(x, b, n), do: error(:padl, {x, b, n})

  @doc """
  Set prefix.bits to either 0 or 1.

  ## Examples

      iex> new(<<1, 1, 1>>, 32) |> bset()
      %Pfx{bits: <<0, 0, 0>>, maxlen: 32}

      iex> new(<<1, 1, 1>>, 32) |> bset(1)
      %Pfx{bits: <<255, 255, 255>>, maxlen: 32}

  """
  @spec bset(t, 0 | 1) :: t | PfxError.t()
  def bset(prefix, bit \\ 0)

  def bset(prefix, bit) when is_pfx(prefix) do
    bit = if bit == 0, do: 0, else: -1
    len = bit_size(prefix.bits)
    %{prefix | bits: <<bit::size(len)>>}
  end

  def bset(x, _) when is_exception(x), do: x
  def bset(x, y), do: error(:bset, {x, y})

  # Numbers

  @doc """
  Slice a *prefix* into a list of smaller pieces, each *newlen* bits long.

  The given *newlen* must be larger than or equal to the prefix' current bit
  length, else it is considered an error.

  ## Examples

      # break out the /26's in a /24
      iex> new(<<10, 11, 12>>, 32)|> slice(26)
      [
        %Pfx{bits: <<10, 11, 12, 0::size(2)>>, maxlen: 32},
        %Pfx{bits: <<10, 11, 12, 1::size(2)>>, maxlen: 32},
        %Pfx{bits: <<10, 11, 12, 2::size(2)>>, maxlen: 32},
        %Pfx{bits: <<10, 11, 12, 3::size(2)>>, maxlen: 32}
      ]

  """
  @spec slice(t, non_neg_integer) :: list(t) | PfxError.t()
  def slice(prefix, newlen)
      when is_pfx(prefix) and is_inrange(newlen, bit_size(prefix.bits), prefix.maxlen) do
    width = newlen - bit_size(prefix.bits)
    max = (1 <<< width) - 1

    for n <- 0..max do
      %Pfx{prefix | bits: <<prefix.bits::bitstring, n::size(width)>>}
    end
  end

  def slice(x, _) when is_exception(x), do: x
  def slice(x, n), do: error(:slice, {x, n})

  @doc """
  Turn *prefix* into a list of `{number, width}`-fields.

  If the actual number of prefix bits are not a multiple of *width*, the last
  field will have a shorter width.

  ## Examples

      iex> new(<<10, 11, 12, 0::1>>, 32)
      ...> |> fields(8)
      [{10, 8}, {11, 8}, {12, 8}, {0, 1}]

      iex> new(<<0xacdc::16>>, 128)
      ...> |> fields(4)
      [{10, 4}, {12, 4}, {13, 4}, {12, 4}]

      iex> new(<<10, 11, 12>>, 32)
      ...> |> fields(1)
      ...> |> Enum.map(fn {x, _} -> x end)
      ...> |> Enum.join("")
      "000010100000101100001100"

  """
  @spec fields(t, non_neg_integer) :: list({non_neg_integer, non_neg_integer}) | PfxError.t()
  def fields(prefix, width) when is_pfx(prefix) and is_integer(width) and width > 0,
    do: fields([], prefix.bits, width)

  def fields(x, _) when is_exception(x), do: x
  def fields(x, w), do: error(:fields, {x, w})

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
  Transform a *prefix* into `{digits, len}` format.

  The *prefix* is padded to its maximum length using `0`'s and the resulting
  bits are grouped into *digits*, each *width*-bits wide.  The resulting *len*
  preserves the original bitstring length.  Note: works best if prefix'
  *maxlen* is a multiple of the *width* used, otherwise *maxlen* cannot be
  inferred from this format in combination with *width*.

  ## Examples

      iex> new(<<10, 11, 12>>, 32) |> digits(8)
      {{10, 11, 12, 0}, 24}

      iex> new(<<0x12, 0x34, 0x56, 0x78>>, 32) |> digits(4)
      {{1, 2, 3, 4, 5, 6, 7, 8}, 32}

      iex> new(<<10, 11, 12, 1::1>>, 32) |> digits(8)
      {{10, 11, 12, 128}, 25}

      iex> new(<<0xacdc::16, 1976::16>>, 128) |> digits(16)
      {{44252, 1976, 0, 0, 0, 0, 0, 0}, 32}

      iex> new(<<255>>, 32)
      ...> |> digits(1)
      ...> |> elem(0)
      ...> |> Tuple.to_list()
      ...> |> Enum.join("")
      "11111111000000000000000000000000"

  """
  @spec digits(t, pos_integer) :: {tuple(), pos_integer} | PfxError.t()
  def digits(%Pfx{} = prefix, width) do
    try do
      digits =
        prefix
        |> padr()
        |> fields(width)
        |> Enum.map(fn {n, _w} -> n end)
        |> List.to_tuple()

      {digits, bit_size(prefix.bits)}
    rescue
      _ -> error(:digits, {prefix, width})
    end
  end

  def digits(x, _) when is_exception(x), do: x
  def digits(x, w), do: error(:digits, {x, w})

  @doc """
  Return the prefix represented by the *digits*, actual *length* and a given
  field *width*.

  Each number/digit in *digits* is turned into a number of *width* bits wide
  and the resulting prefix's *maxlen* is inferred from the number of digits
  given and their *width*.

  Note: if a *digit* does not fit in *width*-bits, only the *width*-least
  significant bits are preserved.

  ## Examples

      iex> undigits({{10, 11, 12, 0}, 24}, 8)
      %Pfx{bits: <<10, 11, 12>>, maxlen: 32}

      iex> undigits({{10, 11, 12, 0}, 24}, 8) |> digits(8)
      {{10, 11, 12, 0}, 24}

      iex> undigits({{-1, -1, 0, 0}, 32}, 8) |> format()
      "255.255.0.0"

  """
  @spec undigits({tuple(), pos_integer}, pos_integer) :: t | PfxError.t()
  def undigits({digits, length}, width) do
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
      _ -> error(:undigits, {{digits, length}, width})
    end
  end

  def undigits(x, _) when is_exception(x), do: x
  def undigits(d, l), do: error(:undigits, {d, l})

  @doc """
  Returns a sibling prefix at distance given by *offset*.

  This basically increases or decreases the number represented by the *prefix*
  bits.

  Note that the length of *prefix.bits* will not change and when cycling
  through all other siblings, you're looking at yourself (i.e. it wraps
  around).

  ## Examples

      # next in line
      iex> new(<<10, 11>>, 32) |> sibling(1)
      %Pfx{bits: <<10, 12>>, maxlen: 32}

      # and the last shall be first
      iex> new(<<10, 11, 0>>, 32) |> sibling(255)
      %Pfx{bits: <<10, 11, 255>>, maxlen: 32}

      # still all in the family
      iex> new(<<10, 11, 0>>, 32) |> sibling(256)
      %Pfx{bits: <<10, 12, 0>>, maxlen: 32}

      # from one end to another
      iex> new(<<0, 0, 0, 0>>, 32) |> sibling(-1)
      %Pfx{bits: <<255, 255, 255, 255>>, maxlen: 32}

      # zero bit-length stays zero bit-length
      iex> new(<<>>, 32) |> sibling(1)
      %Pfx{bits: <<>>, maxlen: 32}

  """
  @spec sibling(t, integer) :: t | PfxError.t()
  def sibling(prefix, offset) when is_pfx(prefix) and is_integer(offset) do
    bsize = bit_size(prefix.bits)
    x = castp(prefix.bits, bit_size(prefix.bits))
    x = x + offset

    %Pfx{prefix | bits: <<x::size(bsize)>>}
  end

  def sibling(x, _) when is_exception(x), do: x
  def sibling(x, o), do: error(:sibling, {x, o})

  @doc """
  The size of *prefix* as determined by its *missing* bits.

  size(prefix) == 2^(prefix.maxlen - bit_size(prefix.bits))

  ## Examples

      iex> new(<<10, 10, 10>>, 32) |> size()
      256

      iex> new(<<10, 10, 10, 10>>, 32) |> size()
      1

  """
  @spec size(t) :: pos_integer | PfxError.t()
  def size(prefix) when is_pfx(prefix),
    do: :math.pow(2, prefix.maxlen - bit_size(prefix.bits)) |> trunc

  def size(x) when is_exception(x), do: x
  def size(x), do: error(:size, x)

  @doc """
  Return the *nth*-member of a given *prefix*.

  A prefix represents a range of (possibly longer) prefixes which can be
  seen as *members* of the prefix.  So a prefix of `n`-bits long represents:
  - 1 prefix of `n+0`-bits long (i.e. itself),
  - 2 prefixes of `n+1`-bits long,
  - 4 prefixes of `n+2`-bits long
  - ..
  - 2^w prefixes of `n+w`-bits long

  where `n+w` <= *prefix.maxlen*.

  Not specifying a *width* assumes the maximum width available.  If a *width*
  is specified, the *nth*-offset is added to the prefix as a number
  *width*-bits wide.  This wraps around since `<<16::4>>` comes out as
  `<<0::4>>`.

  It is considered an error to specify a *width* greater than the amount of
  bits the *prefix* actually has to spare, given its *prefix.bits*-length and its
  *prefix.maxlen*.

  ## Examples

      iex> new(<<10, 10, 10>>, 32) |> member(0)
      %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32}

      iex> new(<<10, 10, 10>>, 32) |> member(255)
      %Pfx{bits: <<10, 10, 10, 255>>, maxlen: 32}

      # wraps around
      iex> new(<<10, 10, 10>>, 32) |> member(256)
      %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32}

      iex> new(<<10, 10, 10>>, 32) |> member(-1)
      %Pfx{bits: <<10, 10, 10, 255>>, maxlen: 32}

      # a full prefix always returns itself
      iex> new(<<10, 10, 10, 10>>, 32) |> member(0)
      %Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}

  """
  @spec member(t, integer) :: t | PfxError.t()
  def member(prefix, nth) when is_pfx(prefix),
    do: member(prefix, nth, prefix.maxlen - bit_size(prefix.bits))

  def member(x, _) when is_exception(x), do: x
  def member(x, y), do: error(:member, {x, y})

  @doc """
  Return the *nth* subprefix for a given *prefix*, using *width* bits.

  ## Examples

      # the first sub-prefix that is 2 bits longer
      iex> new(<<10, 10, 10>>, 32) |> member(0, 2)
      %Pfx{bits: <<10, 10, 10, 0::2>>, maxlen: 32}

      # the second sub-prefix that is 2 bits longer
      iex> new(<<10, 10, 10>>, 32) |> member(1, 2)
      %Pfx{bits: <<10, 10, 10, 1::2>>, maxlen: 32}

  """
  @spec member(t, integer, pos_integer) :: t | PfxError.t()
  def member(pfx, nth, width)
      when is_pfx(pfx) and is_integer(nth) and
             is_inrange(width, 0, pfx.maxlen - bit_size(pfx.bits)),
      do: %{pfx | bits: <<pfx.bits::bits, nth::size(width)>>}

  def member(x, _, _) when is_exception(x), do: x
  def member(x, n, w), do: error(:member, {x, n, w})

  @doc """
  Returns true is prefix x is a member of prefix y

  If either x or y is invalid, member? returns false

  """
  @spec member?(t, t) :: boolean
  def member?(x, y) when is_comparable(x, y) and bit_size(y.bits) <= bit_size(x.bits),
    do: y.bits == truncate(x.bits, bit_size(y.bits))

  def member?(_, _), do: false

  # Format

  @doc ~S"""
  Generic formatter to turn a *prefix* into a string, using several options:
  - `:width`, field width (default 8)
  - `:base`, howto turn a field into a string (default 10, use 16 for hex numbers)
  - `:unit`, how many fields go into 1 section (default 1)
  - `:ssep`, howto join the sections together (default ".")
  - `:lsep`, howto join a mask if required (default "/")
  - `:mask`, whether to add a mask (default false)
  - `:reverse`, whether to reverse fields before grouping/joining (default false)
  - `:padding`, whether to pad out the prefix' bits (default true)

  The defaults are geared towards IPv4 prefixes, but the options should be able
  to accomodate other domains as well.

  Notes:
  - the *prefix.bits*-length is omitted if equal to the *prefix.bits*-size
  - domain specific submodules probably implement their own formatter.

  ## Examples

      iex> new(<<10, 11, 12>>, 32) |> format()
      "10.11.12.0/24"

      # mask not appended as its redundant for a full-sized prefix
      iex> new(<<10, 11, 12, 128>>, 32) |> format()
      "10.11.12.128"

      iex> prefix = new(<<0xacdc::16, 0x1976::16>>, 128)
      iex> format(prefix, width: 16, base: 16, ssep: ":")
      "ACDC:1976:0:0:0:0:0:0/32"
      #
      # similar, but grouping 4 fields, each 4 bits wide, into a single section
      #
      iex> format(prefix, width: 4, base: 16, unit: 4, ssep: ":")
      "ACDC:1976:0000:0000:0000:0000:0000:0000/32"
      #
      # this time, omit the acutal prefix length
      #
      iex> format(prefix, width: 16, base: 16, ssep: ":", mask: false)
      "ACDC:1976:0:0:0:0:0:0"
      #
      # ptr for IPv6 using the nibble format:
      # - dot-separated reversal of all hex digits in the expanded address
      #
      iex> prefix
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
  @spec format(t, Keyword.t()) :: String.t() | PfxError.t()
  def format(prefix, opts \\ [])

  def format(prefix, opts) when is_pfx(prefix) do
    width = Keyword.get(opts, :width, 8)
    base = Keyword.get(opts, :base, 10)
    ssep = Keyword.get(opts, :ssep, ".")
    lsep = Keyword.get(opts, :lsep, "/")
    unit = Keyword.get(opts, :unit, 1)
    mask = Keyword.get(opts, :mask, true)
    reverse = Keyword.get(opts, :reverse, false)
    padding = Keyword.get(opts, :padding, true)

    bitstr =
      prefix
      |> (fn x -> if padding, do: padr(x), else: x end).()
      |> fields(width)
      |> Enum.map(fn {n, _w} -> Integer.to_string(n, base) end)
      |> (fn x -> if reverse, do: Enum.reverse(x), else: x end).()
      |> Enum.chunk_every(unit)
      |> Enum.join(ssep)

    if mask and bit_size(prefix.bits) < prefix.maxlen do
      "#{bitstr}#{lsep}#{bit_size(prefix.bits)}"
    else
      bitstr
    end
  end

  def format(x, _) when is_exception(x), do: x
  def format(x, o), do: error(:format, {x, o})

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

      # sort prefix.bits size first, than on prefix.bits values
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

      # prefixes must have the same maxlen
      iex> compare(new(<<10>>, 32), new(<<10>>, 128))
      %PfxError{
        reason: :compare,
        data: {%Pfx{bits: <<10>>, maxlen: 32}, %Pfx{bits: <<10>>, maxlen: 128}}
      }


  """
  @spec compare(t, t) :: :eq | :lt | :gt | PfxError.t()
  def compare(prefix1, prefix2)
  def compare(x, y) when is_comparable(x, y), do: comparep(x.bits, y.bits)
  def compare(x, _) when is_exception(x), do: x
  def compare(_, y) when is_exception(y), do: y
  def compare(x, y), do: error(:compare, {x, y})

  defp comparep(x, y) when bit_size(x) > bit_size(y), do: :lt
  defp comparep(x, y) when bit_size(x) < bit_size(y), do: :gt
  defp comparep(x, y) when x < y, do: :lt
  defp comparep(x, y) when x > y, do: :gt
  defp comparep(x, y) when x == y, do: :eq

  @doc """
  Contrast two prefixes.

  Contrasting two prefixes will yield one of:
  - `:equal` prefix1 is equal to prefix2
  - `:more` prefix1 is a more specific version of prefix2
  - `:less` prefix1 is a less specific version of prefix2
  - `:left` prefix1 is left-adjacent to prefix2
  - `:right` prefix1 is right-adjacent to prefix2
  - `:disjoint` prefix1 has no match with prefix2 whatsoever.

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
  @spec contrast(t, t) :: :equal | :more | :less | :left | :right | :disjoint | PfxError.t()
  def contrast(prefix1, prefix2)
  def contrast(x, y) when is_comparable(x, y), do: contrastp(x.bits, y.bits)
  def contrast(x, _) when is_exception(x), do: x
  def contrast(_, y) when is_exception(y), do: y
  def contrast(x, y), do: error(:contrast, {x, y})

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
end

defimpl String.Chars, for: Pfx do
  def to_string(prefix) do
    case prefix.maxlen do
      32 -> Pfx.format(prefix)
      48 -> Pfx.format(prefix, base: 16, ssep: ":")
      128 -> Pfx.format(prefix, base: 16, width: 16, ssep: ":")
      _ -> Pfx.format(prefix)
    end
  end
end

defimpl Enumerable, for: Pfx do
  require Pfx

  # invalid Pfx yields a count of 0
  def count(prefix),
    do: {:ok, trunc(:math.pow(2, prefix.maxlen - bit_size(prefix.bits)))}

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

  def slice(prefix) do
    {:ok, size} = count(prefix)
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
