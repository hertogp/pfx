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
  @type t() :: %__MODULE__{bits: bitstring, maxlen: non_neg_integer}

  @typedoc """
  An :inet IPv4 or IPv6 address (tuple)

  """
  @type ip_address :: :inet.ip4_address() | :inet.ip6_address()

  @typedoc """
  An IPv4 prefix ({`t:inet.ip4_address/0`, 0..32}) or an IPv6 prefix ({`t:inet.ip6_address/0`, 0..128}).

  """
  @type ip_prefix :: {:inet.ip4_address(), 0..32} | {:inet.ip6_address(), 0..128}

  @typedoc """
  A prefix expressed as either a `t:Pfx.t/0` struct, an IP address-tuple, an
  address,length-tuple or a CIDR string.

  """
  @type prefix :: t() | ip_address | ip_prefix | String.t()

  # valid prefix lengths to use for nat64
  @nat64_lengths [96, 64, 56, 48, 40, 32]

  # Private Guards

  defguardp is_non_neg_integer(n) when is_integer(n) and n >= 0
  defguardp is_pos_integer(n) when is_integer(n) and n > 0
  defguardp is_inrange(x, y, z) when is_integer(x) and y <= x and x <= z

  defguardp is_8bit(n) when is_integer(n) and -1 < n and n < 256
  defguardp is_ip4len(l) when is_integer(l) and -1 < l and l < 33
  defguardp is_16bit(n) when is_integer(n) and -1 < n and n < 65536
  defguardp is_ip6len(l) when is_integer(l) and -1 < l and l < 129

  defguardp is_ip4(a, b, c, d, l)
            when is_8bit(a) and is_8bit(b) and is_8bit(c) and is_8bit(d) and is_ip4len(l)

  defguardp is_ip6(a, b, c, d, e, f, g, h, l)
            when is_16bit(a) and is_16bit(b) and is_16bit(c) and is_16bit(d) and is_16bit(e) and
                   is_16bit(f) and is_16bit(g) and is_16bit(h) and
                   is_ip6len(l)

  defguardp is_eui48(a, b, c, d, e, f, l)
            when is_8bit(a) and is_8bit(b) and is_8bit(c) and is_8bit(d) and
                   is_8bit(e) and is_8bit(f) and is_inrange(l, 0, 48)

  defguardp is_eui64(a, b, c, d, e, f, g, h, l)
            when is_8bit(a) and is_8bit(b) and is_8bit(c) and is_8bit(d) and
                   is_8bit(e) and is_8bit(f) and is_8bit(g) and is_8bit(h) and
                   is_inrange(l, 0, 64)

  # Guards

  @doc """
  Guard that ensures a given `pfx` is actually valid.
  - it is a `t:Pfx.t/0` struct,
  - `pfx.maxlen` is a `t:non_neg_integer/0`,
  - `bit_size(pfx.bits) <= pfx.maxlen`

  """
  @doc section: :guard
  defguard is_pfx(pfx)
           when is_struct(pfx, __MODULE__) and
                  is_non_neg_integer(pfx.maxlen) and
                  is_bitstring(pfx.bits) and
                  bit_size(pfx.bits) <= pfx.maxlen

  @doc """
  Guard that ensures both prefixes are valid and comparable (same maxlen).

  """
  @doc section: :guard
  defguard is_comparable(x, y)
           when is_pfx(x) and is_pfx(y) and x.maxlen == y.maxlen

  # Helpers

  defp arg_error(reason, data) do
    msg =
      case reason do
        :bitpos ->
          "invalid bit position: #{inspect(data)}"

        :einval ->
          "expected a ipv4/ipv6 CIDR or EUI-48/64 string, got #{inspect(data)}"

        :create ->
          "cannot create a Pfx from: #{inspect(data)}"

        :ip4dig ->
          "expected valid IPv4 digits, got #{inspect(data)}"

        :ip4len ->
          "expected a valid IPv4 prefix length, got #{inspect(data)}"

        :ip6dig ->
          "expected valid IPv6 digits, got #{inspect(data)}"

        :ip6len ->
          "expected a valid IPv6 prefix length, got #{inspect(data)}"

        :maxlen ->
          "expected a non_neg_integer for maxlen, got #{inspect(data)}"

        :nat64 ->
          "expected a valid IPv6 nat64 address, got #{inspect(data)}"

        :nat64len ->
          "nat64 prefix length not in [#{Enum.join(@nat64_lengths, ", ")}], got #{inspect(data)}"

        :nobit ->
          "expected a integer (bit) value 0..1, got #{inspect(data)}"

        :nobits ->
          "expected a non-empty bitstring, got: #{inspect(data)}"

        :nobitstr ->
          "expected a bitstring, got: #{inspect(data)}"

        :nocapacity ->
          "prefix's capacity exceeded: #{inspect(data)}"

        :nocompare ->
          "prefixes have different maxlen's: #{inspect(data)}"

        :noeui ->
          "expected an EUI48/64 prefix, string or tuple, got #{inspect(data)}"

        :noeui64 ->
          "expected an EUI-64 prefix, string or tuple(s), got #{inspect(data)}"

        :noflags ->
          "expected a 16-element tuple of bits, got #{inspect(data)}"

        :nohex ->
          "expected a hexadecimal string, got #{inspect(data)}"

        :noint ->
          "expected an integer, got #{inspect(data)}"

        :noints ->
          "expected all integers, got #{inspect(data)}"

        :noneg ->
          "expected a non_neg_integer, got #{inspect(data)}"

        :noneighbor ->
          "empty prefixes have no neighbor: #{inspect(data)}"

        :nopart ->
          "cannot partition prefixes using #{inspect(data)}"

        # :nopfx ->
        #   "expected a valid %Pfx{}-struct, got #{inspect(data)}"

        :nopos ->
          "expected a pos_integer, got #{inspect(data)}"

        :noundig ->
          "expected {{n1, n2, ..}, length}, got #{inspect(data)}"

        :nowidth ->
          "expected valid width, got #{inspect(data)}"

        :pfx ->
          "expected a valid Pfx struct, got #{inspect(data)}"

        :pfx4 ->
          "expected a valid IPv4 Pfx, got #{inspect(data)}"

        :pfx4full ->
          "expected a full IPv4 address, got #{inspect(data)}"

        :pfx6 ->
          "expected a valid IPv6 Pfx, got #{inspect(data)}"

        :pfx6full ->
          "expected a full IPv6 address, got #{inspect(data)}"

        :range ->
          "invalid index range: #{inspect(data)}"

        reason ->
          "error #{reason}, #{inspect(data)}"
      end

    ArgumentError.exception(msg)
  end

  # cast a series of bits to a number, width bits wide.
  # - used for the binary ops on prefixes
  defp castp(bits, width) do
    bsize = bit_size(bits)
    <<x::size(bsize)>> = bits
    Bitwise.bsl(x, width - bsize)
  end

  # 11:22:33:44:55:66 or 1122.3344.5566 or some weird mix thereof 11-22.33:44.5566
  defp hex([], acc, n),
    do: {acc, n}

  defp hex([x | tail], acc, n) when ?0 <= x and x <= ?9,
    do: hex(tail, <<acc::bits, x - ?0::4>>, n)

  defp hex([x | tail], acc, n) when ?a <= x and x <= ?f,
    do: hex(tail, <<acc::bits, x - ?a + 10::4>>, n)

  defp hex([x | tail], acc, n) when ?A <= x and x <= ?F,
    do: hex(tail, <<acc::bits, x - ?A + 10::4>>, n)

  defp hex([?- | tail], acc, n) when bit_size(acc) in [8, 16, 24, 32, 40, 48, 56],
    do: hex(tail, acc, n + 1)

  defp hex([?: | tail], acc, n) when bit_size(acc) in [8, 16, 24, 32, 40, 48, 56],
    do: hex(tail, acc, n + 1)

  defp hex([?. | tail], acc, n) when bit_size(acc) in [16, 32, 48],
    do: hex(tail, acc, n + 1)

  # turn a EUI-48/64 like string into bits
  @spec hexify(charlist) :: t()
  defp hexify(clist) do
    {bits, hyphens} = hex(clist, <<>>, 0)

    bsize = bit_size(bits)

    case {bsize, hyphens} do
      {48, 2} -> new(bits, bsize)
      {48, 5} -> new(bits, bsize)
      {64, 3} -> new(bits, bsize)
      {64, 7} -> new(bits, bsize)
      _ -> raise ArgumentError
    end
  end

  # split a charlist with length into tuple w/ {'address', length}
  # notes:
  # - ugly code, but a tad faster than multiple func's w/ signatures
  # - crude length "parser" -> '1.1.1.1/024' => {'1.1.1.1', 24}
  # - TODO: add when y != ?0 resp. when x != nil to 1st and 3rd clause in case
  # tail => then masks with leading zero's will yield an error
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

  # optionally drops some lsb's
  defp truncate(bits, max) do
    if bit_size(bits) > max do
      <<part::bitstring-size(max), _::bitstring>> = bits
      part
    else
      bits
    end
  end

  # API

  # notes:
  # - new/1 and new/2 *MUST* raise an ArgumentError if it fails
  # - many functions use `new` to translate other representations into a
  #   `Pfx` struct and call themselves again with that struct

  @doc """
  Returns the address portion of given prefix without applying the mask (if
  any).

  Note that this has no real effect on a `t:Pfx.t/0` or an `t:ip_address/0` since
  there is no mask to ignore.  Since no mask is applied, this always returns a
  full prefix without any bits masked off.  Raises `ArgumentError` if given an
  invalid prefix.

  ## Examples

      iex> address("1.2.3.4/16")
      "1.2.3.4"

      iex> address({{1, 2, 3, 4}, 16})
      {{1, 2, 3, 4}, 32}

      iex> address({{0xacdc, 0x1976, 0, 0, 0, 0, 0, 1}, 64})
      {{0xacdc, 0x1976, 0, 0, 0, 0, 0, 1}, 128}

      iex> pfx = "1.2.3.4/24"
      iex> new(pfx).bits
      <<1, 2, 3>>
      iex> new(address(pfx)).bits
      <<1, 2, 3, 4>>

      # no real effect
      iex> address("1.2.3.4")
      "1.2.3.4"

      iex> address({1, 2, 3, 4})
      {1, 2, 3, 4}

      iex> address({0xacdc, 0x1976, 0, 0, 0, 0, 0, 1})
      {0xacdc, 0x1976, 0, 0, 0, 0, 0, 1}

      iex> new("1.2.3.4/16") |> address()
      %Pfx{bits: <<1, 2>>, maxlen: 32}

  """
  @spec address(prefix) :: prefix
  def address(prefix) do
    # ensure we raise on invalid prefix lengths
    new(prefix)

    case prefix do
      x when is_binary(x) -> String.split(x, "/") |> hd()
      {{a, b, c, d}, _} -> {a, b, c, d}
      {{a, b, c, d, e, f, g, h}, _} -> {a, b, c, d, e, f, g, h}
      _ -> prefix
    end
    |> new()
    |> marshall(prefix)
  rescue
    err -> raise err
  end

  @doc """
  Returns the bit-value at given `position` in `pfx`.

  A bit position is a `0`-based index from the left with range `0..maxlen-1`.
  A negative bit position is taken relative to `Pfx.maxlen`.  Bits that are
  masked (bit position in the range of `bit_size(pfx.bits) .. pfx.maxlen - 1`)
  always yield `0`.

  ## Examples

      iex> bit("1.2.0.0", 14)
      1

      # same bit
      iex> bit("1.2.0.0", -18)
      1

      iex> bit("1.2.0.0/16", 14)
      1

      iex> bit({1, 2, 0, 0}, 14)
      1

      iex> bit({{1, 2, 0, 0}, 16}, 14)
      1

      iex> bit(%Pfx{bits: <<1, 2>>, maxlen: 32}, 14)
      1

      # 'masked' bits are deemed to be `0`
      iex> bit("1.2.0.0/16", 24)
      0

      # errors out on invalid positions
      iex> bit("255.255.255.255", 33)
      ** (ArgumentError) invalid bit position: 33

      iex> bit("10.10.0.0/16", -33)
      ** (ArgumentError) invalid bit position: -33

  """
  @spec bit(prefix, integer) :: 0 | 1
  def bit(pfx, position) when is_pfx(pfx) and is_integer(position) do
    pos = if position < 0, do: position + pfx.maxlen, else: position
    if pos < 0 or pos >= pfx.maxlen, do: raise(arg_error(:bitpos, position))
    bitp(pfx, pos)
  end

  def bit(pfx, pos) when is_integer(pos) do
    new(pfx)
    |> bit(pos)
  rescue
    err -> raise err
  end

  def bit(_, pos),
    do: raise(arg_error(:noint, pos))

  defp bitp(pfx, pos) when pos < bit_size(pfx.bits) do
    <<_::size(pos), bit::1, _::bitstring>> = pfx.bits
    bit
  end

  defp bitp(_, _), do: 0

  @doc """
  Returns `length` bits, starting at `position` for given `pfx`.

  Negative `position`'s are relative to the end of the `pfx.bits` bitstring,
  while negative `length` will collect bits going left instead of to the
  right.  Note that the bit at given `position` is always included in the
  result regardless of direction.  Finally, a `length` of `0` results in
  an empty bitstring.

  ## Examples

      # last two bytes
      iex> bits("128.0.128.1", 16, 16)
      <<128, 1>>

      iex> bits({128, 0, 128, 1}, 16, 16) # same
      <<128, 1>>

      iex> bits({128, 0, 128, 1}, 31, -16) # same
      <<128, 1>>

      iex> bits({{128, 0, 128, 1}, 32}, 31, -16) # same
      <<128, 1>>

      # first byte
      iex> bits(%Pfx{bits: <<128, 0, 0, 1>>, maxlen: 32}, 0, 8)
      <<128>>

      # same as
      iex> bits(%Pfx{bits: <<128, 0, 0, 1>>, maxlen: 32}, 7, -8)
      <<128>>

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
  @spec bits(prefix(), integer, integer) :: bitstring()
  def bits(prefix, position, length)

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

  def bits(pfx, position, length) do
    new(pfx)
    |> bits(position, length)
  rescue
    err -> raise err
  end

  @spec bitsp(t(), integer, integer) :: bitstring
  defp bitsp(pfx, pos, len) when is_pfx(pfx) do
    # x = padr(pfx) |> new(), the latter no longer required for dialyzer
    x = padr(pfx)
    <<_::size(pos), part::bitstring-size(len), _::bitstring>> = x.bits
    part
  end

  @doc """
  Returns the concatenation of 1 or more series of bits of the given `pfx`.

  ## Examples

      iex> bits("1.2.3.4", [{0, 8}, {-1, -8}])
      <<1, 4>>

      iex> bits("1.2.3.0/24", [{0, 8}, {-1, -8}])
      <<1, 0>>

      iex> bits({1, 2, 3, 4}, [{0, 8}, {-1, -8}])
      <<1, 4>>

      iex> bits({{1, 2, 3, 0}, 24}, [{0,8}, {-1, -8}])
      <<1, 0>>

      iex> bits(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}, [{0,8}, {-1, -8}])
      <<1, 4>>

  """
  @spec bits(prefix, [{integer, integer}]) :: bitstring
  def bits(pfx, ranges) when is_list(ranges) do
    x = new(pfx)

    Enum.map(ranges, fn {pos, len} -> bits(x, pos, len) end)
    |> Enum.reduce(<<>>, &joinbitsp/2)
  rescue
    err -> raise err
  end

  defp joinbitsp(x, y), do: <<y::bitstring, x::bitstring>>

  @doc """
  Returns a bitwise NOT of the bits in `pfx`.

  Results are returned in the same representation as given `pfx`.

  ## Examples

      iex> bnot("255.255.0.0")
      "0.0.255.255"

      iex> bnot({255, 255, 0, 0})
      {0, 0, 255, 255}

      iex> bnot({{255, 255, 0, 0}, 32})
      {{0, 0, 255, 255}, 32}

      iex> new(<<255, 255, 0, 0>>, 32) |> bnot()
      %Pfx{bits: <<0, 0, 255, 255>>, maxlen: 32}

      iex> bnot("5323:e689::/32")
      "acdc:1976:0:0:0:0:0:0/32"

  """
  @spec bnot(prefix) :: prefix
  def bnot(pfx) when is_pfx(pfx) do
    width = bit_size(pfx.bits)

    x =
      castp(pfx.bits, width)
      |> Bitwise.bnot()

    %Pfx{pfx | bits: <<x::size(width)>>}
  end

  def bnot(pfx) do
    new(pfx)
    |> bnot()
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Returns a bitwise AND of `pfx1` and `pfx2`.

  Both prefixes must have the same `maxlen`.  The resulting prefix will have
  the same number of bits as the first argument.

  ## Examples

      iex> band("10.10.10.10", "255.255.0.0")
      "10.10.0.0"

      iex> band("10.10.10.0/24", "255.255.0.0")
      "10.10.0.0/24"

      iex> x = new(<<128, 129, 130, 131>>, 32)
      iex> y = new(<<255, 255>>, 32)
      iex> band(x, y)
      %Pfx{bits: <<128, 129, 0, 0>>, maxlen: 32}
      iex>
      iex> band(y,x)
      %Pfx{bits: <<128, 129>>, maxlen: 32}

      # results adopt the format of the first argument
      iex> band("1.2.3.4", {255, 255, 0, 0})
      "1.2.0.0"

      iex> band({1, 2, 3, 4}, "255.255.0.0")
      {1, 2, 0, 0}

      iex> band({{1, 2, 3, 4}, 24}, {255, 255, 0, 0})
      {{1, 2, 0, 0}, 24}

      # honoring the ancient tradition
      iex> band("1.2.3.4", "255.255")
      "1.0.0.4"

      iex> band("10.10.0.0/16", "255.0.0.0/24")
      "10.0.0.0/16"

  """
  @spec band(prefix, prefix) :: prefix
  def band(pfx1, pfx2) when is_comparable(pfx1, pfx2) do
    maxlen = pfx1.maxlen
    x = castp(pfx1.bits, maxlen)
    y = castp(pfx2.bits, maxlen)
    z = Bitwise.band(x, y)
    %Pfx{pfx1 | bits: truncate(<<z::size(maxlen)>>, bit_size(pfx1.bits))}
  end

  def band(pfx1, pfx2) when is_pfx(pfx1) and is_pfx(pfx2),
    do: raise(arg_error(:nocompare, {pfx1, pfx2}))

  def band(pfx1, pfx2) do
    new(pfx1)
    |> band(new(pfx2))
    |> marshall(pfx1)
  rescue
    err -> raise err
  end

  @doc """
  Returns a bitwise OR of `pfx1` and `pfx2`.

  Both prefixes must have the same `maxlen`. The result will have the same
  number of bits as its first argument.

  ## Examples

      iex> bor("1.2.3.4", "0.0.255.0")
      "1.2.255.4"

      iex> bor({1, 2, 3, 4}, "0.0.255.0")
      {1, 2, 255, 4}

      iex> bor({{1, 2, 3, 4}, 16}, {0, 255, 255, 0})
      {{1, 255, 0, 0}, 16}

      # same sized `bits`
      iex> x = new(<<10, 11, 12, 13>>, 32)
      iex> y = new(<<0, 0, 255, 255>>, 32)
      iex> bor(x, y)
      %Pfx{bits: <<10, 11, 255, 255>>, maxlen: 32}

      # same `maxlen` but differently sized `bits`: missing bits are considered to be `0`
      iex> bor("10.11.12.13", "255.255.0.0/16")
      "255.255.12.13"

      # result has same number of bits as the first prefix
      iex> bor("10.10.0.0/16", "255.255.255.255")
      "255.255.0.0/16"

  """
  @spec bor(prefix, prefix) :: prefix
  def bor(pfx1, pfx2) when is_comparable(pfx1, pfx2) do
    width = pfx1.maxlen
    x = castp(pfx1.bits, width)
    y = castp(pfx2.bits, width)
    z = Bitwise.bor(x, y)
    %Pfx{pfx1 | bits: truncate(<<z::size(width)>>, bit_size(pfx1.bits))}
  end

  def bor(pfx1, pfx2) when is_pfx(pfx1) and is_pfx(pfx2),
    do: raise(arg_error(:nocompare, {pfx1, pfx2}))

  def bor(pfx1, pfx2) do
    new(pfx1)
    |> bor(new(pfx2))
    |> marshall(pfx1)
  rescue
    err -> raise err
  end

  @doc """
  Returns a bitwise XOR of `pfx1` and `pfx2`.

  Both prefixes must have the same `maxlen`.  The result has the same number of
  bits as the first argument.

  ## Examples

      iex> bxor("10.11.12.13", "255.255.0.0")
      "245.244.12.13"

      iex> bxor({10, 11, 12, 13}, {255, 255, 0, 0})
      {245, 244, 12, 13}

      # mix 'n match
      iex> bxor({{10, 11, 12, 13}, 32}, "255.255.0.0")
      {{245, 244, 12, 13}, 32}

      iex> x = new(<<10, 11, 12, 13>>, 32)
      iex> y = new(<<255, 255>>, 32)
      iex> bxor(x, y)
      %Pfx{bits: <<245, 244, 12, 13>>, maxlen: 32}

      iex> bxor("255.255.0.0/16", "10.11.12.13")
      "245.244.0.0/16"

  """
  @spec bxor(prefix, prefix) :: prefix
  def bxor(pfx1, pfx2) when is_comparable(pfx1, pfx2) do
    width = pfx1.maxlen
    x = castp(pfx1.bits, width)
    y = castp(pfx2.bits, width)
    z = Bitwise.bxor(x, y)
    %Pfx{pfx1 | bits: truncate(<<z::size(width)>>, bit_size(pfx1.bits))}
  end

  def bxor(pfx1, pfx2) when is_pfx(pfx1) and is_pfx(pfx2),
    do: raise(arg_error(:nocompare, {pfx1, pfx2}))

  def bxor(pfx1, pfx2) do
    new(pfx1)
    |> bxor(new(pfx2))
    |> marshall(pfx1)
  rescue
    err -> raise err
  end

  @doc """
  Rotates the bits of `pfx` by `n` positions.

  Positive `n` rotates right, negative rotates left.  The length of the
  resulting bits stays the same.

  ## Examples

      iex> brot("1.2.3.4", 8)
      "4.1.2.3"

      iex> brot("1.2.3.4", -8)
      "2.3.4.1"

      iex> brot({1, 2, 3, 4}, 8)
      {4, 1, 2, 3}

      iex> brot({{1, 2, 3, 4}, 32}, -8)
      {{2, 3, 4, 1}, 32}

      # note: the `bits` <<1, 2>> get rotated (!)
      iex> brot("1.2.0.0/16", 8)
      "2.1.0.0/16"

      iex> brot(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}, 8)
      %Pfx{bits: <<4, 1, 2, 3>>, maxlen: 32}

  """
  @spec brot(prefix, integer) :: prefix
  def brot(prefix, integer)

  def brot(%Pfx{bits: <<>>} = pfx, _) when is_pfx(pfx),
    do: pfx

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

  def brot(pfx, n) when is_integer(n) do
    new(pfx)
    |> brot(n)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def brot(_, n),
    do: raise(arg_error(:noint, n))

  @doc """
  Sets all bits of `pfx` to either `0` or `1`.

  If `bit` is not provided, it defaults to `0`.

  ## Examples

      iex> bset("1.1.1.0/24")
      "0.0.0.0/24"

      iex> bset("1.1.1.0/24", 1)
      "255.255.255.0/24"

      iex> bset({{1, 1, 1, 0}, 24}, 1)
      {{255, 255, 255, 0}, 24}

      iex> bset(%Pfx{bits: <<1, 1, 1>>, maxlen: 32})
      %Pfx{bits: <<0, 0, 0>>, maxlen: 32}

      iex> bset(%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, 1)
      %Pfx{bits: <<255, 255, 255>>, maxlen: 32}

  """
  @spec bset(prefix, 0 | 1) :: prefix
  def bset(pfx, bit \\ 0)

  def bset(pfx, bit) when is_pfx(pfx) and (bit === 0 or bit === 1) do
    bit = -1 * bit
    len = bit_size(pfx.bits)
    %{pfx | bits: <<bit::size(len)>>}
  end

  def bset(pfx, bit) when bit === 0 or bit === 1 do
    new(pfx)
    |> bset(bit)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def bset(_, bit),
    do: raise(arg_error(:nobit, bit))

  @doc """
  Performs an arithmetic shift left of the bits in `pfx` by `n` positions.

  A positive `n` shifts to the left, negative `n` shifts to the right.  The
  length of the bits stays the same.

  ## Examples

      iex> bsl("1.2.3.4", 1)
      "2.4.6.8"

      iex> bsl("1.2.0.0/16", 2)
      "4.8.0.0/16"

      iex> bsl({1, 2, 3, 4}, 2)
      {4, 8, 12, 16}

      # note: the `bits` <<1, 2>> get shifted left 2 bits
      iex> bsl({{1, 2, 0, 0}, 16}, 2)
      {{4, 8, 0, 0}, 16}

      iex> bsl(%Pfx{bits: <<1, 2>>, maxlen: 32}, 2)
      %Pfx{bits: <<4, 8>>, maxlen: 32}

      iex> bsl(%Pfx{bits: <<1, 2>>, maxlen: 32}, -2)
      %Pfx{bits: <<0, 64>>, maxlen: 32}

  """
  @spec bsl(prefix, integer) :: prefix
  def bsl(pfx, n) when is_pfx(pfx) and is_integer(n) do
    width = bit_size(pfx.bits)

    x =
      castp(pfx.bits, width)
      |> Bitwise.bsl(n)

    %Pfx{pfx | bits: <<x::size(width)>>}
  end

  def bsl(pfx, n) when is_integer(n) do
    new(pfx)
    |> bsl(n)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def bsl(_, n),
    do: raise(arg_error(:noint, n))

  @doc """
  Performs an arithmetic shift right the bits in `pfx` by `n` positions.

  A negative `n` actually shifts to the left.  The length of the bits stays the
  same.

  ## Examples

      iex> bsr("1.2.0.0/16", 2)
      "0.64.0.0/16"

      # no mask, so all 32 bits get shifted
      iex> bsr({1, 2, 0, 0}, 2)
      {0, 64, 128, 0}

      iex> bsr({{1, 2, 0, 0}, 16}, 2)
      {{0, 64, 0, 0}, 16}

      iex> bsr(%Pfx{bits: <<1, 2>>, maxlen: 32}, 2)
      %Pfx{bits: <<0, 64>>, maxlen: 32}

      # now shift to the left
      iex> bsr(%Pfx{bits: <<1, 2>>, maxlen: 32}, -2)
      %Pfx{bits: <<4, 8>>, maxlen: 32}

  """
  @spec bsr(prefix, integer) :: prefix
  def bsr(pfx, n) when is_pfx(pfx) and is_integer(n) do
    width = bit_size(pfx.bits)

    x =
      castp(pfx.bits, width)
      |> Bitwise.bsr(n)

    %Pfx{pfx | bits: <<x::size(width)>>}
  end

  def bsr(pfx, n) when is_integer(n) do
    new(pfx)
    |> bsr(n)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def bsr(_, n),
    do: raise(arg_error(:noint, n))

  @doc """
  Casts a `pfx` to an integer.

  After right padding the given `pfx`, its bits are interpreted as a number of
  maxlen bits wide.  Empty prefixes evaluate to `0`, since all 'missing' bits
  are taken to be zero (even if `pfx.maxlen` is `0`).

  See `cut/3` for how this capability might be useful.

  ## Examples

      iex> cast("255.255.0.0")
      4294901760

      iex> cast("255.255.0.0/16")
      4294901760

      iex> cast({255, 255, 0, 0})
      4294901760

      iex> cast({{255, 255, 0, 0}, 32})
      4294901760

      iex> cast(%Pfx{bits: <<255, 255>>, maxlen: 32})
      4294901760

      iex> new(<<4294901760::32>>, 32)
      %Pfx{bits: <<255, 255, 0, 0>>, maxlen: 32}

      # missing bits filled in as `0`s
      iex> cast(%Pfx{bits: <<255>>, maxlen: 16})
      65280

      iex> cast(%Pfx{bits: <<-1::128>>, maxlen: 128})
      340282366920938463463374607431768211455

      iex> cast(%Pfx{bits: <<>>, maxlen: 8})
      0

      # a bit weird, but:
      iex> cast(%Pfx{bits: <<>>, maxlen: 0})
      0

  """
  @spec cast(prefix) :: non_neg_integer
  def cast(pfx) when is_pfx(pfx),
    do: castp(pfx.bits, pfx.maxlen)

  def cast(pfx) do
    new(pfx)
    |> cast()
  rescue
    err -> raise err
  end

  @doc ~S"""
  Compares `pfx1` to `pfx2` for sorting purposes.

  The result is one of:
  - `:eq` prefix1 is equal to prefix2
  - `:lt` prefix1 has more bits *or* lies to the left of prefix2
  - `:gt` prefix1 has less bits *or* lies to the right of prefix2

  The prefixes must have the same *maxlen* and are first compared by size
  (i.e. a *shorter* prefix is considered *larger*), and second on their
  bitstring value.

  ## Examples

      iex> compare("10.0.0.0/8", "11.0.0.0/8")
      :lt

      iex> compare("10.0.0.0/8", {{11, 0, 0, 0}, 8})
      :lt

      iex> compare({10, 0, 0, 0}, {{11, 0, 0, 0}, 16})
      :lt

      iex> compare(new(<<10>>, 32), new(<<11>>, 32))
      :lt

      # sort on prefixes, first on bit_size than bits-values

      iex> list = ["10.11.0.0/16", "10.10.10.0/24", "10.10.0.0/16"]
      iex> Enum.sort(list, Pfx)
      [
        "10.10.10.0/24",
        "10.10.0.0/16",
        "10.11.0.0/16"
      ]
      # whereas regular sort does:
      #
      iex> Enum.sort(list)
      [
        "10.10.0.0/16",
        "10.10.10.0/24",
        "10.11.0.0/16"
      ]

      iex> list = [new(<<10, 11>>, 32), new(<<10,10,10>>, 32), new(<<10,10>>, 32)]
      iex> Enum.sort(list, Pfx)
      [
        %Pfx{bits: <<10, 10, 10>>, maxlen: 32},
        %Pfx{bits: <<10, 10>>, maxlen: 32},
        %Pfx{bits: <<10, 11>>, maxlen: 32}
      ]

      # not advisable, but mixed representations are possible as well
      iex> l = ["10.11.0.0/16", {{10, 10, 10, 0}, 24}, %Pfx{bits: <<10, 10>>, maxlen: 32}]
      iex> Enum.sort(l, Pfx)
      [
        {{10, 10, 10, 0}, 24},
        %Pfx{bits: <<10, 10>>, maxlen: 32},
        "10.11.0.0/16",
      ]

      # note: all prefixes must have the same `maxlen`
      iex> compare(new(<<10>>, 32), new(<<10>>, 128))
      ** (ArgumentError) prefixes have different maxlen's: {%Pfx{bits: "\n", maxlen: 32}, %Pfx{bits: "\n", maxlen: 128}}

  """
  @spec compare(prefix, prefix) :: :eq | :lt | :gt
  def compare(pfx1, pfx2)

  def compare(x, y) when is_comparable(x, y),
    do: comparep(x.bits, y.bits)

  def compare(x, y) when is_pfx(x) and is_pfx(y),
    do: raise(arg_error(:nocompare, {x, y}))

  def compare(x, y) do
    new(x)
    |> compare(new(y))
  rescue
    err -> raise err
  end

  defp comparep(x, y) when bit_size(x) > bit_size(y), do: :lt
  defp comparep(x, y) when bit_size(x) < bit_size(y), do: :gt
  defp comparep(x, y) when x < y, do: :lt
  defp comparep(x, y) when x > y, do: :gt
  defp comparep(x, y) when x == y, do: :eq

  @doc """
  Contrasts `pfx1` to `pfx2`.

  Contrasting two prefixes yields one of:
  - `:equal` pfx1 is equal to pfx2
  - `:more` pfx1 is a more specific version of pfx2
  - `:less` pfx1 is a less specific version of pfx2
  - `:left` pfx1 is left-adjacent to pfx2
  - `:right` pfx1 is right-adjacent to pfx2
  - `:disjoint` pfx1 has no match with pfx2 whatsoever.

  ## Examples

      iex> contrast("10.10.0.0/16", "10.10.0.0/16")
      :equal

      iex> contrast("10.10.10.0/24", "10.10.0.0/16")
      :more

      iex> contrast("10.0.0.0/8", "10.255.255.0/24")
      :less

      iex> contrast("1.2.3.0/24", "1.2.4.0/24")
      :left

      iex> contrast("1.2.3.4/30", "1.2.3.0/30")
      :right

      iex> contrast("10.10.0.0/16", "9.0.0.0/8")
      :disjoint

      iex> contrast("10.10.0.0/16", %Pfx{bits: <<10,12>>, maxlen: 32})
      :disjoint

  """
  @spec contrast(prefix, prefix) :: :equal | :more | :less | :left | :right | :disjoint
  def contrast(pfx1, pfx2)

  def contrast(x, y) when is_comparable(x, y),
    do: contrastp(x.bits, y.bits)

  def contrast(x, y) when is_pfx(x) and is_pfx(y),
    do: raise(arg_error(:nocompare, {x, y}))

  def contrast(x, y) do
    new(x)
    |> contrast(new(y))
  rescue
    err -> raise err
  end

  defp contrastp(x, y) when x == y,
    do: :equal

  defp contrastp(x, y) when bit_size(x) > bit_size(y),
    do: if(y == truncate(x, bit_size(y)), do: :more, else: :disjoint)

  defp contrastp(x, y) when bit_size(x) < bit_size(y),
    do: if(x == truncate(y, bit_size(x)), do: :less, else: :disjoint)

  defp contrastp(x, y) do
    size = bit_size(x)
    <<n::size(size)>> = x
    <<m::size(size)>> = y

    case n - m do
      1 -> :right
      -1 -> :left
      _ -> :disjoint
    end
  end

  @doc """
  Cuts out a series of bits and turns it into its own `Pfx`.

  Extracts the bits and returns a new `t:Pfx.t/0` with `bits` set to the
  bits extracted and `maxlen` set to the length of the `bits`-string.

  ## Examples

      iex> cut("::ffff:192.0.2.128", -1, -32)
      "192.0.2.128"

      iex> teredo = new("2001:0:4136:e378:8000:63bf:3fff:fdd2")
      iex> # client
      iex> cut(teredo, 96, 32) |> bnot() |> format()
      "192.0.2.45"
      iex> # udp port
      iex> cut(teredo, 80, 16) |> bnot() |> cast()
      40000
      iex> # teredo server
      iex> cut(teredo, 32, 32) |> format()
      "65.54.227.120"
      iex> # flags
      iex> cut(teredo, 64, 16) |> digits(1) |> elem(0)
      {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

  'Masked' bits are considered to be zero.

      # extract 2nd and 3rd byte:
      iex> %Pfx{bits: <<255, 255>>, maxlen: 32} |> cut(8, 16)
      %Pfx{bits: <<255, 0>>, maxlen: 16}

  Less useful, but cut will mirror the representation given:

      iex> cut("10.11.12.13", 8, 16)
      "11.12"

      iex> cut({1, 2, 3, 4}, 16, 16)
      {3, 4}

      iex> cut({{1, 2, 0, 0}, 16}, 8, 16)
      {{2, 0}, 16}


  Extraction must stay within `maxlen` of given `pfx`.

      # cannot exceed boundaries though:
      iex> %Pfx{bits: <<255, 255>>, maxlen: 32} |> cut(8, 32)
      ** (ArgumentError) invalid index range: {8, 32}

  """
  @spec cut(prefix, integer, integer) :: prefix
  def cut(pfx, start, length) when is_pfx(pfx) do
    bits = bits(pfx, start, length)
    new(bits, bit_size(bits))
  rescue
    _ -> raise arg_error(:range, {start, length})
  end

  def cut(pfx, start, length) do
    new(pfx)
    |> cut(start, length)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Returns a `{{digit, ..}, length}` representation of given `pfx`.

  The `pfx` is padded to its maximum length using `0`'s and the resulting
  bits are grouped into *digits*, each `width`-bits wide.  The resulting `length`
  denotes the prefix' original bit_size.

  Note: works best if the prefix' `maxlen` is a multiple of the `width` used,
  otherwise `maxlen` cannot be inferred from this format by `tuple_size(digits)
  * width` (e.g. by `Pfx.undigits/2`)

  ## Examples

      iex> digits("10.11.12.0/24", 8)
      {{10, 11, 12, 0}, 24}

      # mask is applied first
      iex> digits("10.11.12.13/24", 8)
      {{10, 11, 12, 0}, 24}

      iex> digits("acdc:1976::/32", 16)
      {{44252, 6518, 0, 0, 0, 0, 0, 0}, 32}

      iex> digits({{0xacdc, 0x1976, 0, 0, 0, 0, 0, 0}, 32}, 16)
      {{44252, 6518, 0, 0, 0, 0, 0, 0}, 32}

      iex> digits(%Pfx{bits: <<10, 11, 12>>, maxlen: 32}, 8)
      {{10, 11, 12, 0}, 24}

      iex> digits(%Pfx{bits: <<10, 11, 12, 1::1>>, maxlen: 32}, 8)
      {{10, 11, 12, 128}, 25}

      iex> digits(%Pfx{bits: <<0x12, 0x34, 0x56, 0x78>>, maxlen: 128}, 4)
      {{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 32}

  """
  @spec digits(prefix, pos_integer) :: {tuple(), pos_integer}
  def digits(pfx, width) when is_pfx(pfx) and is_pos_integer(width) do
    digits =
      pfx
      |> padr()
      |> fields(width)
      |> Enum.map(fn {n, _w} -> n end)
      |> List.to_tuple()

    {digits, bit_size(pfx.bits)}
  end

  def digits(pfx, width) when is_pos_integer(width) do
    new(pfx)
    |> digits(width)
  rescue
    err -> raise err
  end

  def digits(_, width),
    do: raise(arg_error(:nowidth, width))

  @doc """
  Drops `count` lsb bits from given `pfx`.

  If `count` exceeds the actual number of bits in `pfx`, simply drops all
  bits.

  ## Examples

      iex> drop("1.2.3.0/31", 1)
      "1.2.3.0/30"

      iex> drop("1.2.3.2/31", 1)
      "1.2.3.0/30"

      iex> drop("1.2.3.128/25", 1)
      "1.2.3.0/24"

      # drops all
      iex> drop("1.2.3.0/24", 512)
      "0.0.0.0/0"

      iex> drop("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 64)
      "2001:db8:85a3:0:0:0:0:0/64"

      iex> drop({1, 2, 3, 4}, 8)
      {1, 2, 3, 0}

      iex> drop({{1, 2, 3, 4}, 32}, 16)
      {{1, 2, 0, 0}, 16}

      iex> drop(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}, 16)
      %Pfx{bits: <<1, 2>>, maxlen: 32}

  """
  @spec drop(prefix, non_neg_integer) :: prefix
  def drop(pfx, count) when is_pfx(pfx) and is_non_neg_integer(count) do
    cond do
      count < bit_size(pfx.bits) -> %{pfx | bits: truncate(pfx.bits, bit_size(pfx.bits) - count)}
      true -> %{pfx | bits: <<>>}
    end
  end

  def drop(pfx, count) when is_non_neg_integer(count) do
    new(pfx)
    |> drop(count)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def drop(_, count),
    do: raise(arg_error(:nodrop, "expected a non_neg_integer for count, got: #{inspect(count)}"))

  @doc """
  Returns a list of `{number, width}`-fields for given `pfx`.

  If `bit_size(pfx.bits)` is not a multiple of `width`, the last
  `{number, width}`-tuple, will have a smaller width.

  ## Examples

      iex> fields("10.11.12.13", 8)
      [{10, 8}, {11, 8}, {12, 8}, {13, 8}]

      iex> fields({10, 11, 12, 13}, 8)
      [{10, 8}, {11, 8}, {12, 8}, {13, 8}]

      iex> fields({{10, 11, 12, 0}, 24}, 8)
      [{10, 8}, {11, 8}, {12, 8}]

      iex> fields(%Pfx{bits: <<10, 11, 12, 13>>, maxlen: 32}, 8)
      [{10, 8}, {11, 8}, {12, 8}, {13, 8}]

      # pfx.bits is not a multiple of 8, hence the {0, 1} at the end
      iex> fields("10.11.12.0/25", 8)
      [{10, 8}, {11, 8}, {12, 8}, {0, 1}]

      iex> new(<<0xacdc::16>>, 128) |> fields(4)
      [{10, 4}, {12, 4}, {13, 4}, {12, 4}]

      # only 1 field with less bits than given width of 64
      iex> new(<<255, 255>>, 32) |> fields(64)
      [{65535, 16}]

  """
  @spec fields(prefix, non_neg_integer) :: list({non_neg_integer, non_neg_integer})
  def fields(pfx, width) when is_pfx(pfx) and is_integer(width) and width > 0,
    do: fieldsp([], pfx.bits, width)

  def fields(pfx, width) when is_integer(width) and width > 0 do
    new(pfx)
    |> fields(width)
  rescue
    err -> raise err
  end

  def fields(_, width),
    do: raise(arg_error(:nowidth, width))

  defp fieldsp(acc, <<>>, _width), do: Enum.reverse(acc)

  defp fieldsp(acc, bits, width) when bit_size(bits) >= width do
    <<num::size(width), rest::bitstring>> = bits
    fieldsp([{num, width} | acc], rest, width)
  end

  defp fieldsp(acc, bits, width) do
    w = bit_size(bits)
    <<num::size(w)>> = bits
    fieldsp([{num, w} | acc], "", width)
  end

  @doc """
  Returns the first full length prefix from the set represented by `pfx`.

  ## Examples

      iex> first("10.10.10.1/24")
      "10.10.10.0"

      iex> first("acdc:1976::/32")
      "acdc:1976:0:0:0:0:0:0"

      # a full address is its own this-network
      iex> first({10, 10, 10, 1})
      {10, 10, 10, 1}

      iex> first({{10, 10, 10, 1}, 24})
      {{10, 10, 10, 0}, 32}

      iex> first(%Pfx{bits: <<10, 10, 10>>, maxlen: 32})
      %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32}

      iex> first(%Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128})
      %Pfx{bits: <<0xACDC::16, 0x1976::16, 0::96>>, maxlen: 128}

  """
  @spec first(prefix) :: prefix
  def first(pfx) do
    new(pfx)
    |> padr(0)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Flips a single bit at `position` in given `pfx`.

  A negative `position` is relative to the end of the `pfx.bits` bitstring.
  It is an error to point to a bit outside the range of available bits.

  ## Examples

      iex> flip("255.255.254.0", 23)
      "255.255.255.0"

      iex> flip("255.255.255.0", -9)
      "255.255.254.0"

      # flip the 7th bit
      iex> flip("0088.8888.8888", 6)
      "02-88-88-88-88-88"

      iex> flip({1, 2, 3, 0}, 24)
      {1, 2, 3, 128}

      # flip last bit
      iex> flip({{1, 2, 3, 128}, 25}, 24)
      {{1, 2, 3, 0}, 25}

      iex> flip({{1, 2, 3, 128}, 25}, -1)
      {{1, 2, 3, 0}, 25}

      iex> flip(%Pfx{bits: <<1, 2, 3, 1::1>>, maxlen: 32}, -1)
      %Pfx{bits: <<1, 2, 3, 0::1>>, maxlen: 32}

  """
  @spec flip(prefix, integer) :: prefix
  def flip(pfx, position) when is_pfx(pfx) and is_integer(position) do
    pos = if position < 0, do: position + bit_size(pfx.bits), else: position

    if pos < 0 or pos >= bit_size(pfx.bits),
      do: raise(arg_error(:bitpos, position))

    <<left::size(pos), bit::1, right::bitstring>> = pfx.bits
    bit = bit - 1
    %{pfx | bits: <<left::size(pos), bit::1, right::bitstring>>}
  end

  def flip(pfx, position) when is_integer(position) do
    new(pfx)
    |> flip(position)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def flip(_pfx, pos),
    do: raise(arg_error(:bitpos, pos))

  @doc ~S"""
  Formats `pfx` as a string, using several options:
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

      iex> format(%Pfx{bits: <<10, 11, 12>>, maxlen: 32})
      "10.11.12.0/24"

      iex> format({{10, 11, 12, 0}, 24})
      "10.11.12.0/24"

      iex> format({10, 11, 12, 0})
      "10.11.12.0"

      # non-sensical, but there you go
      iex> format("10.11.12.0/24")
      "10.11.12.0/24"

      # bitstring, note that mask is applied when new creates the `pfx`
      iex> format("1.2.3.4/24", width: 1, base: 2, unit: 8, mask: false)
      "00000001.00000010.00000011.00000000"

      # mask not appended as its redundant for a full-sized prefix
      iex> format(%Pfx{bits: <<10, 11, 12, 13>>, maxlen: 32})
      "10.11.12.13"

      iex> pfx = new(<<0xacdc::16, 0x1976::16>>, 128)
      iex> format(pfx, width: 16, base: 16, ssep: ":")
      "acdc:1976:0:0:0:0:0:0/32"
      #
      # similar, but grouping 4 fields, each 4 bits wide, into a single section
      #
      iex> format(pfx, width: 4, base: 16, unit: 4, ssep: ":")
      "acdc:1976:0000:0000:0000:0000:0000:0000/32"
      #
      # this time, omit the acutal pfx length
      #
      iex> format(pfx, width: 16, base: 16, ssep: ":", mask: false)
      "acdc:1976:0:0:0:0:0:0"
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
  @spec format(prefix, Keyword.t()) :: String.t()
  def format(pfx, opts \\ [])

  # - NOTE: String.Chars, when using Pfx.format, MUST always provide at least 1 option
  def format(pfx, []) when is_pfx(pfx) and pfx.maxlen in [32, 48, 64, 128] do
    "#{pfx}"
  end

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

    string = if pfx.maxlen == 128, do: String.downcase(string), else: string

    if mask and bit_size(pfx.bits) < pfx.maxlen do
      "#{string}#{lsep}#{bit_size(pfx.bits)}"
    else
      string
    end
  end

  def format(pfx, opts) do
    new(pfx)
    |> format(opts)
  rescue
    err -> raise err
  end

  @doc """
  Creates a `Pfx` struct for given hexadecimal `string`.

  This always returns a `t:Pfx.t/0` struct.  A list of punctuation characters
  can be supplied as a second argument and defaults to `[?:, ?-, ?.]`.  Note
  that '/' should not be used as that separates the mask from the rest of the
  binary.  Punctuation characters are simply ignored and no positional checks
  are performed.

  Contrary to `Pfx.from_mac/1`, this function turns a random hexadecimal into a
  prefix.  Do not use this to create a prefix out of an IPv6 address.

  ## Examples

      iex> from_hex("1-2:3.4:a-bcdef")
      %Pfx{bits: <<0x12, 0x34, 0xAB, 0xCD, 0xEF>>, maxlen: 40}

      iex> from_hex("1-2:3.4:a-bcdef/16")
      %Pfx{bits: <<0x12, 0x34>>, maxlen: 40}

      iex> from_hex("1|2|3|A|B|C|DEF", [?|])
      %Pfx{bits: <<0x12, 0x3A, 0xBC, 0xDE, 0xF::4>>, maxlen: 36}

      iex> from_hex("ABC")
      %Pfx{bits: <<0xAB, 0xC::4>>, maxlen: 12}

      # not for IPv6 addresses ..
      iex> from_hex("2001::1")
      %Pfx{bits: <<0x20, 0x01, 0x1::4>>, maxlen: 20}


  """
  @spec from_hex(binary) :: t()
  def from_hex(string, punctuation \\ [?:, ?-, ?.])
      when is_binary(string) and is_list(punctuation) do
    charlist = String.to_charlist(string)

    {address, mask} = splitp(charlist, [])

    {bits, _} =
      address
      |> Enum.filter(fn c -> c not in punctuation end)
      |> hex(<<>>, 0)

    %Pfx{bits: truncate(bits, mask), maxlen: bit_size(bits)}
  rescue
    _ -> raise arg_error(:nohex, string)
  end

  @doc """
  Creates a `Pfx` struct from a EUI48/64 strings or tuples.

  Parsing strings is somewhat relaxed since punctuation characters are
  interchangeable as long as their positions are correct.

  Note that `new/1` tries to parse binaries as IP prefixes first and would turn
  an EUI-64 using ":" for punctuation into an IPv6 address.  Similarly, a
  8-element tuple is seen as IPv6 address.  Hence, if you really need to parse
  EUI-64 binaries with ":", or have EUI-48/64 tuples, use this function.

  `from_mac/1` also accepts a `Pfx` struct, but only if its maxlen is either
  `48` or `64`.  If not, an `ArgumentError` is raised.

  ## Examples

      iex> from_mac("11:22:33:44:55:66")
      %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66>>, maxlen: 48}

      iex> from_mac("11-22-33-44-55-66")
      %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66>>, maxlen: 48}

      iex> from_mac("1122.3344.5566")
      %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66>>, maxlen: 48}

      iex> from_mac({0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
      %Pfx{bits: <<0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff>>, maxlen: 48}

      # keep the OUI
      iex> from_mac({{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, 24})
      %Pfx{bits: <<0xaa, 0xbb, 0xcc>>, maxlen: 48}

      iex> from_mac("11:22:33:44:55:66/24")
      %Pfx{bits: <<0x11, 0x22, 0x33>>, maxlen: 48}

      # a EUI-64
      iex> from_mac("11-22-33-44-55-66-77-88")
      %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88>>, maxlen: 64}

      iex> from_mac("11:22:33:44:55:66:77:88")
      %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88>>, maxlen: 64}

      iex> from_mac("11:22:33:44:55:66:77:88/24")
      %Pfx{bits: <<0x11, 0x22, 0x33>>, maxlen: 64}

      iex> from_mac({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
      %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88>>, maxlen: 64}

      iex> from_mac({{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, 24})
      %Pfx{bits: <<0x11, 0x22, 0x33>>, maxlen: 64}

      # note: from_mac reads nibbles so each address element must be 2 nibbles (!)
      iex> from_mac("01:02:03:04:05:06:07:08")
      %Pfx{bits: <<0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8>>, maxlen: 64}

      # mix and match
      # ":" and "-" are interchangeable
      iex> from_mac("11:22-33:44-55:66")
      %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66>>, maxlen: 48}

  """
  @spec from_mac(t() | binary | tuple) :: t()
  def from_mac(string) when is_binary(string) do
    charlist = String.to_charlist(string)
    {address, mask} = splitp(charlist, [])

    hexify(address)
    |> keep(mask)
  rescue
    _ -> raise arg_error(:noeui, string)
  end

  # from EUI-48 tuples
  def from_mac({a, b, c, d, e, f}),
    do: from_mac({{a, b, c, d, e, f}, 48})

  # splitp may produce nil to signal absence of /len in binary
  def from_mac({{a, b, c, d, e, f}, nil}),
    do: from_mac({{a, b, c, d, e, f}, 48})

  def from_mac({{a, b, c, d, e, f}, len}) when is_eui48(a, b, c, d, e, f, len) do
    <<bits::bitstring-size(len), _::bitstring>> = <<a::8, b::8, c::8, d::8, e::8, f::8>>
    %Pfx{bits: bits, maxlen: 48}
  end

  # from EUI-64 tuples
  def from_mac({a, b, c, d, e, f, g, h}),
    do: from_mac({{a, b, c, d, e, f, g, h}, 64})

  # splitp may produce nil to signal absence of /len in binary
  def from_mac({{a, b, c, d, e, f, g, h}, nil}),
    do: from_mac({{a, b, c, d, e, f, g, h}, 64})

  def from_mac({{a, b, c, d, e, f, g, h}, len}) when is_eui64(a, b, c, d, e, f, g, h, len) do
    <<bits::bitstring-size(len), _::bitstring>> =
      <<a::8, b::8, c::8, d::8, e::8, f::8, g::8, h::8>>

    %Pfx{bits: bits, maxlen: 64}
  end

  # from Pfx
  def from_mac(pfx) when is_pfx(pfx) do
    case pfx.maxlen do
      48 -> pfx
      64 -> pfx
      _ -> raise arg_error(:noeui, pfx)
    end
  end

  def from_mac(arg),
    do: raise(arg_error(:noeui, arg))

  @doc """
  Returns the `nth` full length prefix in given `pfx`.

  Note that offset `nth` wraps around. See `Pfx.member/2`.

  ## Examples

      iex> host("10.10.10.0/24", 128)
      "10.10.10.128"

      iex> host({{10, 10, 10, 0}, 24}, 128)
      {{10, 10, 10, 128}, 32}

      iex> host(%Pfx{bits: <<10, 10, 10>>, maxlen: 32}, 128)
      %Pfx{bits: <<10, 10, 10, 128>>, maxlen: 32}

      # wraps around
      iex> host("10.10.10.0/24", 256)
      "10.10.10.0"

  """
  @spec host(prefix, integer) :: prefix
  def host(pfx, nth) when is_integer(nth) do
    new(pfx)
    |> member(nth)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def host(_pfx, nth),
    do: raise(arg_error(:noint, nth))

  @doc """
  Returns a list of address prefixes for given `pfx`.

  ## Examples

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

      iex> hosts(%Pfx{bits: <<10, 10, 10, 0::6>>, maxlen: 32})
      [
        %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10, 1>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10, 2>>, maxlen: 32},
        %Pfx{bits: <<10, 10, 10, 3>>, maxlen: 32}
      ]

  """
  @spec hosts(prefix) :: list(prefix)
  def hosts(pfx),
    do: for(ip <- new(pfx), do: marshall(ip, pfx))

  @doc """
  Inserts `bits` into `pfx`-s bitstring, starting at `position`.

  The resulting bitstring is silently clipped to the `pfx.maxlen`.

  Valid bit positions are `bits_size(pfx.bits) .. min(pfx.maxlen-1,
  bit_size(pfx.bits))`.  A position of `0` will prepend the `bits`, while a
  position of `bit_size(pfx.bits)` will append the `bits` as long as the prefix
  is not a full length prefix already.

  A negative position is taken relative to the end.  Note that this cannot
  be used for appending bits, since `-1` refers to the last actual bit and
  there is no such thing as `-0` ..

  ## Examples

      # prepend bits
      iex> insert("0.0.0.0/0", <<255>>, 0)
      "255.0.0.0/8"

      # append bits
      iex> insert("255.255.0.0/16", <<255>>, 16)
      "255.255.255.0/24"

      # cannot append to a full prefix, positions go from 0..31
      iex> insert("1.2.3.4", <<255>>, 32)
      ** (ArgumentError) invalid bit position: 32

      # but inserting inside the bitstring, is ok
      iex> insert("1.2.3.4", <<255>>, 16)
      "1.2.255.3"

      # turn EUI48 into a modified EUI64
      iex> new("0088.8888.8888")
      ...> |> new(64)
      ...> |> flip(6)
      ...> |> insert(<<0xFF, 0xFE>>, 24)
      %Pfx{bits: <<0x02, 0x88, 0x88, 0xFF, 0xFE, 0x88, 0x88, 0x88>>, maxlen: 64}

      # sliently clips to pfx's maxlen
      iex> insert("1.2.3.0/24", <<255, 255, 255, 255>>, 0)
      "255.255.255.255"

      iex> insert("1.2.3.0/24", <<255, 255, 255, 255>>, 24)
      "1.2.3.255"

  """
  @spec insert(prefix, bitstring, integer) :: prefix
  def insert(pfx, bits, position)
      when is_pfx(pfx) and is_bitstring(bits) and is_integer(position) do
    pos = if position < 0, do: position + bit_size(pfx.bits), else: position

    if pos < 0 or pos > bit_size(pfx.bits) or pos >= pfx.maxlen,
      do: raise(arg_error(:bitpos, position))

    <<left::bitstring-size(pos), right::bitstring>> = pfx.bits
    %{pfx | bits: truncate(<<left::bitstring, bits::bitstring, right::bitstring>>, pfx.maxlen)}
  end

  def insert(pfx, bits, position) when is_bitstring(bits) and is_integer(position) do
    new(pfx)
    |> insert(bits, position)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def insert(_pfx, bits, pos) when is_integer(pos),
    do: raise(arg_error(:nobitstr, bits))

  def insert(_pfx, _bit, pos),
    do: raise(arg_error(:bitpos, pos))

  @doc """
  Returns the inverted mask for given `pfx`.

  The result is always a full length prefix.

  ## Examples

      iex> inv_mask("10.10.10.0/25")
      "0.0.0.127"

      iex> inv_mask({10, 10, 10, 0})
      {0, 0, 0, 0}

      iex> inv_mask({{10, 10, 10, 0}, 25})
      {{0, 0, 0, 127}, 32}

      iex> inv_mask(%Pfx{bits: <<10, 10, 10, 0::1>>, maxlen: 32})
      %Pfx{bits: <<0, 0, 0, 127>>, maxlen: 32}

  """
  @spec inv_mask(prefix) :: prefix
  def inv_mask(pfx) do
    new(pfx)
    |> bset(0)
    |> padr(1)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Keeps `count` msb bits of given `pfx`.

  If `count` exceeds the actual number of bits in `pfx.bits`, it keeps all
  bits.

  ## Examples

      iex> keep("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 64)
      "2001:db8:85a3:0:0:0:0:0/64"

      iex> keep("1.2.3.0/31", 30)
      "1.2.3.0/30"

      iex> keep("1.2.3.2/31", 30)
      "1.2.3.0/30"

      iex> keep("1.2.3.128/25", 24)
      "1.2.3.0/24"

      iex> keep("1.2.3.0/24", 512)
      "1.2.3.0/24"

      iex> keep({1, 2, 3, 4}, 24)
      {1, 2, 3, 0}

      iex> keep({{1, 2, 3, 4}, 32}, 16)
      {{1, 2, 0, 0}, 16}

      iex> keep(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}, 16)
      %Pfx{bits: <<1, 2>>, maxlen: 32}

  """
  @spec keep(prefix, non_neg_integer) :: prefix
  def keep(pfx, count) when is_pfx(pfx) and is_non_neg_integer(count) do
    cond do
      count < bit_size(pfx.bits) -> %{pfx | bits: truncate(pfx.bits, count)}
      true -> pfx
    end
  end

  def keep(pfx, count) when is_non_neg_integer(count) do
    new(pfx)
    |> keep(count)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  # take nil to mean keep all, used possibly by new(binary)
  def keep(pfx, nil),
    do: pfx

  def keep(_, count),
    do: raise(arg_error(:noneg, "expected a non_neg_integer for count, got: #{inspect(count)}"))

  @doc """
  Returns the last full length prefix from the set represented by `pfx`.

  ## Examples

      iex> last("10.10.0.0/16")
      "10.10.255.255"

      # a full address is its own last address
      iex> last({10, 10, 10, 1})
      {10, 10, 10, 1}

      iex> last({{10, 10, 10, 1}, 30})
      {{10, 10, 10, 3}, 32}

      iex> last(%Pfx{bits: <<10, 10, 10>>, maxlen: 32})
      %Pfx{bits: <<10, 10, 10, 255>>, maxlen: 32}

      iex> last(%Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128})
      %Pfx{bits: <<0xACDC::16, 0x1976::16, -1::96>>, maxlen: 128}

      iex> last("acdc:1976::/112")
      "acdc:1976:0:0:0:0:0:ffff"

  """
  @spec last(prefix) :: prefix
  def last(pfx) do
    new(pfx)
    |> padr(1)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Returns a representation of `pfx` (a `t:Pfx.t/0`-struct) in the form of `original`.

  The exact original is not required, the `pfx` is transformed by the shape of
  the `original` argument: string vs two-element tuple vs tuple.  If none of
  the three shapes match, the `pfx` is returned unchanged.

  This is used to allow results to be the same shape as their (first) argument
  that needed to turn into a `t:Pfx.t/0` for some calculation.

  Note that when turning a prefix into a address-tuple, an address-tuple comes out
  which is the first full length prefix in the set represented by `pfx`.

  ## Examples

      # original is a string
      iex> marshall(%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, "any string really")
      "1.1.1.0/24"

      # original is any two-element tuple
      iex> marshall(%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, {0,0})
      {{1, 1, 1, 0}, 24}

      # original is any other tuple, actually turns prefix into this-network address
      iex> marshall(%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, {})
      {1, 1, 1, 0}

      # original is a Pfx struct
      iex> marshall(%Pfx{bits: <<1, 1, 1>>, maxlen: 32}, %Pfx{bits: <<>>, maxlen: 0})
      %Pfx{bits: <<1, 1, 1>>, maxlen: 32}

      iex> marshall(new("1.1.1.1"), {})
      {1, 1, 1, 1}

  """
  @spec marshall(t(), prefix) :: prefix
  def marshall(pfx, original) when is_pfx(pfx) do
    width = if pfx.maxlen == 128, do: 16, else: 8

    cond do
      is_binary(original) -> "#{pfx}"
      is_tuple(original) and tuple_size(original) == 2 -> digits(pfx, width)
      is_tuple(original) -> digits(pfx, width) |> elem(0)
      true -> pfx
    end
  end

  def marshall(pfx, _),
    do: pfx

  @doc """
  Returns the mask for given `pfx`.

  The result is always a full length prefix.

  ## Examples

      iex> mask("10.10.10.0/25")
      "255.255.255.128"

      iex> mask({10, 10, 10, 0})
      {255, 255, 255, 255}

      iex> mask({{10, 10, 10, 0}, 25})
      {{255, 255, 255, 128}, 32}

      iex> mask("acdc:1976::/32")
      "ffff:ffff:0:0:0:0:0:0"

      # some prefix with some other maxlen
      iex> mask(%Pfx{bits: <<10, 10, 0::1>>, maxlen: 20})
      %Pfx{bits: <<255, 255, 8::4>>, maxlen: 20}

  """
  @spec mask(prefix) :: prefix
  def mask(pfx) do
    new(pfx)
    |> bset(1)
    |> padr(0)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Applies `mask` to given `prefix`.

  The `mask` is applied through a bitwise AND after which the result is trimmed
  to the size of `mask`.  Both `prefix` and `mask` do not need to be full
  length prefixes.

  Options include:
  - `:inv_mask`, if `true` the `mask` is inverted before applying it (default: `false`)
  - `:trim`, if `false` the result is not trimmed to the size of `mask` (default: `true`)

  Note that both `prefix` and `mask` must be of the same type (same maxlen).

  ## Examples

      # trims result by default
      iex> mask("1.1.1.1", "255.255.255.0")
      "1.1.1.0/24"

      iex> mask("1.1.1.1", "255.255.255.0") |> first()
      "1.1.1.0"

      # same as above
      iex> mask("1.1.1.1", "255.255.255.0", trim: false)
      "1.1.1.0"

      # mirror representation
      iex> mask({{1, 1, 1, 1}, 32}, {255, 255, 255, 0})
      {{1, 1, 1, 0}, 24}

      iex> mask("1.1.1.1", "255.0.0.255")
      "1.0.0.1"

      # mask need not be full length prefix
      iex> mask("1.1.1.1", "255.255.0.0/16")
      "1.1.0.0/16"

      iex> mask("1.1.1.1", "255.255.0.0/16", trim: false)
      "1.1.0.0"

      # neither does prefix
      iex> mask("1.1.1.0/24", "255.255.0.0/16")
      "1.1.0.0/16"

      # no trim, so prefix length stays 24 bits
      iex> mask("1.1.1.0/24", "255.255.0.0/16", trim: false)
      "1.1.0.0/24"

      # inverted mask
      iex> mask("10.16.0.0", "0.3.255.255", inv_mask: true)
      ...> |> (fn x -> {x, first(x), last(x)} end).()
      {"10.16.0.0/14", "10.16.0.0", "10.19.255.255"}

  """
  @spec mask(prefix, prefix, Keyword.t()) :: prefix
  def mask(prefix, mask, opts \\ [])

  def mask(prefix, mask, opts) when is_pfx(mask) do
    pfx = new(prefix)

    unless is_comparable(pfx, mask),
      do: raise(arg_error(:nocompare, {"#{pfx}", "#{mask}"}))

    mask =
      if Keyword.get(opts, :inv_mask, false),
        do: bnot(mask),
        else: mask

    mask =
      if Keyword.get(opts, :trim, true),
        do: %{mask | bits: trimp(mask.bits)},
        else: padr(mask)

    len = min(bit_size(pfx.bits), bit_size(mask.bits))

    mask
    |> band(pfx)
    |> keep(len)
    |> marshall(prefix)
  rescue
    err -> raise err
  end

  def mask(prefix, mask, opts) do
    mask(prefix, new(mask), opts)
  rescue
    err -> raise err
  end

  @doc """
  Returns the `nth`-member of a given `pfx`.

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
  `width`-bits wide.  This wraps around the available address space.

  ## Examples

      iex> member("10.10.10.0/24", 255)
      "10.10.10.255"

      # wraps around
      iex> member("10.10.10.0/24", 256)
      "10.10.10.0"

      iex> member({{10, 10, 10, 0}, 24}, 255)
      {{10, 10, 10, 255}, 32}

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

  """
  @spec member(prefix, integer) :: prefix
  def member(pfx, nth) when is_pfx(pfx) and is_integer(nth),
    do: member(pfx, nth, pfx.maxlen - bit_size(pfx.bits))

  def member(pfx, nth) when is_integer(nth) do
    new(pfx)
    |> member(nth)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def member(_, nth),
    do: raise(arg_error(:noint, nth))

  @doc """
  Returns the `nth` member in the set represented by `pfx`, using `width` bits.

  ## Examples

      iex> member("10.10.10.0/24", 1, 2)
      "10.10.10.64/26"

      iex> member("10.10.10.0/24", 2, 2)
      "10.10.10.128/26"

      iex> member({{10, 10, 10, 0}, 24}, 2, 2)
      {{10, 10, 10, 128}, 26}

      # the first member that is 2 bits longer
      iex> member(%Pfx{bits: <<10, 10, 10>>, maxlen: 32}, 0, 2)
      %Pfx{bits: <<10, 10, 10, 0::2>>, maxlen: 32}

      # the second member that is 2 bits longer
      iex> member(%Pfx{bits: <<10, 10, 10>>, maxlen: 32}, 1, 2)
      %Pfx{bits: <<10, 10, 10, 1::2>>, maxlen: 32}

  """
  @spec member(prefix, integer, pos_integer) :: prefix
  def member(pfx, nth, width)
      when is_pfx(pfx) and is_integer(nth) and is_integer(width) do
    unless 0 <= width and width <= pfx.maxlen - bit_size(pfx.bits),
      do: raise(arg_error(:nowidth, width))

    # is_inrange(width, 0, pfx.maxlen - bit_size(pfx.bits)),
    %{pfx | bits: <<pfx.bits::bits, nth::size(width)>>}
  end

  def member(pfx, nth, width) when is_pfx(pfx) and is_integer(nth),
    do: raise(arg_error(:nowidth, width))

  def member(pfx, nth, width) when is_pfx(pfx) and is_integer(width),
    do: raise(arg_error(:noint, nth))

  def member(pfx, nth, width) do
    new(pfx)
    |> member(nth, width)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Returns true is prefix `pfx1` is a member of prefix `pfx2`

  If either `prfx1` or `pfx2` is invalid or they are of different types,
  member? simply returns false.

  ## Examples

      iex> member?("10.10.10.10", "10.0.0.0/8")
      true

      iex> member?({10, 10, 10, 10}, "10.0.0.0/8")
      true

      iex> member?({{10, 10, 10, 10}, 24}, "10.0.0.0/8")
      true

      iex> member?({{11, 0, 0, 0}, 8}, {{10, 0, 0, 0}, 8})
      false

      iex> member?(%Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}, %Pfx{bits: <<10>>, maxlen: 32})
      true

      # bad prefix
      iex> member?("10.10.10.10", "10.10.10.256/24")
      false

  """
  @spec member?(prefix, prefix) :: boolean
  def member?(pfx1, pfx2)
      when is_comparable(pfx1, pfx2) and bit_size(pfx2.bits) <= bit_size(pfx1.bits),
      do: pfx2.bits == truncate(pfx1.bits, bit_size(pfx2.bits))

  def member?(pfx1, pfx2) when is_pfx(pfx1) and is_pfx(pfx2),
    do: false

  def member?(pfx1, pfx2) do
    try do
      member?(new(pfx1), new(pfx2))
    rescue
      _ -> false
    end
  end

  @doc """
  Returns the neighboring prefix for `pfx`, such that both can be combined in a
  supernet.

  ## Examples

      iex> neighbor("1.1.1.128/25")
      "1.1.1.0/25"

      iex> neighbor("1.1.1.0/25")
      "1.1.1.128/25"

      iex> neighbor({1, 1, 1, 1})
      {1, 1, 1, 0}

      iex> neighbor({{1, 1, 1, 128}, 25})
      {{1, 1, 1, 0}, 25}

      iex> neighbor(%Pfx{bits: <<1, 1, 1, 1::1>>, maxlen: 32})
      %Pfx{bits: <<1, 1, 1, 0::1>>, maxlen: 32}

  """
  @spec neighbor(prefix) :: prefix
  def neighbor(pfx) do
    x = new(pfx)
    size = bit_size(x.bits)

    if size == 0 do
      # empty prefix doesn't have a neigbor, really.
      raise arg_error(:noneighbor, pfx)
    else
      offset = 1 - 2 * bit(x, bit_size(x.bits) - 1)
      sibling(x, offset) |> marshall(pfx)
    end
  rescue
    err -> raise err
  end

  @doc """
  Creates a new `t:Pfx.t/0`-prefix.

  Create a new prefix from:
  - from a bitstring and a maximum length, truncating the bits as needed,
  - from a `t:Pfx.t/0` prefix and a new maxlen, again truncating as needed,

  ## Examples

      iex> new(<<10, 10>>, 32)
      %Pfx{bits: <<10, 10>>, maxlen: 32}

      iex> new(<<10, 10>>, 8)
      %Pfx{bits: <<10>>, maxlen: 8}

      # changing 'maxlen' usually changes the prefix' meaning
      iex> new(%Pfx{bits: <<10, 10>>, maxlen: 32}, 128)
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

  @doc ~S"""
  Creates a new prefix from address tuples/binaries or raises `ArgumentError`.

  Use:
  - a binary in
    [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing)-notation,
  - a binary in EUI-48 or EUI-64 format (EUI-64 must be using hyphens !)
  - an {`t:ip_address/0`, `length`}-tuple to truncate the bits to `length`.
  - an ipv4 or ipv6 `t:ip_address/0` tuple directly for a full address, or
  - a `t:Pfx.t/0` struct
  to create a new PFx struct.

  To avoid a possible `ArgumentError`, use `Pfx.parse/1` or `Pfx.parse/2` instead.
  To avoid applying the mask, use `Pfx.address/1` then apply `Pfx.new/1` if needed.

  Binaries are processed by `:inet.parse_address/1`, so be aware of IPv4 shorthand
  notations that may yield surprising results, since digits are taken to be:
  - `d1.d2.d3.d4` -> `d1.d2.d3.d4` (full address)
  - `d1.d2.d3` -> `d1.d2.0.d3`
  - `d1.d2` -> `d1.0.0.d2`
  - `d1` -> `0.0.0.d1`

  If `:inet.parse_address/1` fails to create an IPv4 or IPv6 address, an
  attempt is made to parse the binary as an EUI-48 or EUI-64 MAC address.
  Parsing EUI's is somewhat relaxed, punctuation chars "-", ":", "." are
  interchangeable, but their positions should be correct.

  Note that EUI-64's that use ":"-punctuation are indistinguishable from IPv6,
  e.g.  "11:22:33:44:55:66:77:88".  Use `from_mac/1` when in doubt about
  punctuations used while parsing MAC addresses.

  ## Examples

      # from CIDR strings
      iex> new("10.10.0.0")
      %Pfx{bits: <<10, 10, 0, 0>>, maxlen: 32}

      iex> new("10.10.10.10/16")
      %Pfx{bits: <<10, 10>>, maxlen: 32}

      # ipv6 string
      iex> new("acdc:1976::/32")
      %Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128}

      # from an {address-tuple, length}
      iex> new({{0xacdc, 0x1976, 0, 0, 0, 0, 0, 0}, 32})
      %Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128}

      iex> new({{10, 10, 0, 0}, 16})
      %Pfx{bits: <<10, 10>>, maxlen: 32}

      # from an address-tuple
      iex> new({10, 10, 0, 0})
      %Pfx{bits: <<10, 10, 0, 0>>, maxlen: 32}

      # from a struct
      iex> new(%Pfx{bits: <<10, 10>>, maxlen: 32})
      %Pfx{bits: <<10, 10>>, maxlen: 32}

      # 10.10/16 is interpreted as 10.0.0.10/16 (!)
      iex> new("10.10/16")
      %Pfx{bits: <<10, 0>>, maxlen: 32}

      # some EUI-48's
      iex> new("aa:bb:cc:dd:ee:ff")
      %Pfx{bits: <<0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff>>, maxlen: 48}

      iex> new("aa-bb-cc-dd-ee-ff")
      %Pfx{bits: <<0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff>>, maxlen: 48}

      iex> new("aabb.ccdd.eeff")
      %Pfx{bits: <<0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff>>, maxlen: 48}

      # keep only OUI
      iex> new("aa-bb-cc-dd-ee-ff/24")
      %Pfx{bits: <<0xaa, 0xbb, 0xcc>>, maxlen: 48}

      # some EUI-64's
      iex> new("11-22-33-44-55-66-77-88")
      %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88>>, maxlen: 64}

      iex> new("1122.3344.5566.7788")
      %Pfx{bits: <<0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88>>, maxlen: 64}

      # but note the maxlen here ...
      iex> new("11:22:33:44:55:66:77:88")
      %Pfx{bits: <<0x11::16, 0x22::16, 0x33::16, 0x44::16, 0x55::16, 0x66::16, 0x77::16, 0x88::16>>, maxlen: 128}

      iex> try do
      ...>   new("1.1.1.256")
      ...> rescue
      ...>   x -> Exception.message(x)
      ...> end
      "expected a ipv4/ipv6 CIDR or EUI-48/64 string, got \"1.1.1.256\""

  """
  @spec new(prefix) :: t()
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

  # from ipv4/ipv6 CIDR binary or EUI-48/64 (w/ hyphens only)
  def new(string) when is_binary(string) do
    charlist = String.to_charlist(string)
    {address, mask} = splitp(charlist, [])

    case :inet.parse_address(address) do
      {:ok, digits} -> new({digits, mask})
      {:error, _} -> hexify(address) |> keep(mask)
    end
  rescue
    _ -> raise arg_error(:einval, string)
  end

  def new(prefix),
    do: raise(arg_error(:create, prefix))

  @doc """
  Pads the bits in `pfx` on the left to its full length using `0`-bits.

  ## Examples

      iex> padl("1.2.0.0/16")
      "0.0.1.2"

      iex> padl({{1, 2, 0, 0}, 16})
      {{0, 0, 1, 2}, 32}

      iex> padl(%Pfx{bits: <<1, 2>>, maxlen: 32})
      %Pfx{bits: <<0, 0, 1, 2>>, maxlen: 32}

  """
  @spec padl(prefix) :: prefix
  def padl(pfx) when is_pfx(pfx),
    do: padl(pfx, 0, pfx.maxlen)

  def padl(pfx) do
    new(pfx)
    |> padl()
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Left pad the `pfx.bits` to its full length using either `0` or `1`-bits.

  ## Examples

      iex> padl("1.2.0.0/16", 1)
      "255.255.1.2"

      iex> padl({{1, 2, 0, 0}, 16}, 1)
      {{255, 255, 1, 2}, 32}

      iex> padl(%Pfx{bits: <<1, 2>>, maxlen: 32}, 1)
      %Pfx{bits: <<255, 255, 1, 2>>, maxlen: 32}

  """
  @spec padl(prefix, 0 | 1) :: prefix
  def padl(pfx, bit) when is_pfx(pfx) and (bit === 0 or bit === 1),
    do: padl(pfx, bit, pfx.maxlen)

  def padl(pfx, bit) when bit === 0 or bit === 1 do
    new(pfx)
    |> padl(bit)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def padl(_, bit),
    do: raise(arg_error(:nobit, bit))

  @doc """
  Pads the bits in `pfx` on the Left with `n` bits of either `0` or `1`'s.

  ## Examples

      iex> padl("255.255.0.0/16", 0, 16)
      "0.0.255.255"

      iex> padl("255.255.0.0/16", 1, 16)
      "255.255.255.255"

      iex> padl({{255, 255, 0, 0}, 16}, 0, 16)
      {{0, 0, 255, 255}, 32}

      iex> padl(%Pfx{bits: <<255, 255>>, maxlen: 32}, 0, 16)
      %Pfx{bits: <<0, 0, 255, 255>>, maxlen: 32}

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

  def padl(pfx, bit, n) when is_integer(n) and n >= 0 and (bit === 0 or bit === 1) do
    new(pfx)
    |> padl(bit, n)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def padl(_, bit, n) when bit === 0 or bit === 1,
    do: raise(arg_error(:noneg, n))

  def padl(_, bit, _),
    do: raise(arg_error(:nobit, bit))

  @doc """
  Pads the bits in `pfx` on the right to its full length using `0`-bits.

  The result is always a full prefix with `maxlen` bits.

  ## Examples

      # already a full address
      iex> padr("1.2.3.4")
      "1.2.3.4"

      # mask applied first, then padded with zero's
      iex> padr("1.2.3.4/16")
      "1.2.0.0"

      # mask applied first, than padded with zero's
      iex> padr({{1, 2, 0, 0}, 16})
      {{1, 2, 0, 0}, 32}

      iex> padr(%Pfx{bits: <<1, 2>>, maxlen: 32})
      %Pfx{bits: <<1, 2, 0, 0>>, maxlen: 32}

  """
  @spec padr(prefix) :: prefix
  def padr(pfx) when is_pfx(pfx),
    do: padr(pfx, 0, pfx.maxlen)

  def padr(pfx) do
    new(pfx)
    |> padr()
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Pads the bits in `pfx` on the right to its full length using either `0` or
  `1`-bits.

  ## Examples

      iex> padr("1.2.0.0/16", 1)
      "1.2.255.255"

      iex> padr({{1, 2, 0, 0}, 16}, 1)
      {{1, 2, 255, 255}, 32}

      # nothing to padr, already a full prefix
      iex> padr("1.2.0.0", 1)
      "1.2.0.0"

      iex> padr(%Pfx{bits: <<1, 2>>, maxlen: 32}, 1)
      %Pfx{bits: <<1, 2, 255, 255>>, maxlen: 32}

  """
  @spec padr(prefix, 0 | 1) :: prefix
  def padr(pfx, bit) when is_pfx(pfx) and (bit === 0 or bit === 1),
    do: padr(pfx, bit, pfx.maxlen)

  def padr(pfx, bit) when bit === 0 or bit === 1,
    do: padr(new(pfx), bit) |> marshall(pfx)

  def padr(_, bit),
    do: raise(arg_error(:nobit, bit))

  @doc """
  Pads the bits in `pfx` on the right with `n` bits of either `0` or `1`'s.

  The result is clipped at `maxlen` bits without warning.

  ## Examples

      # expand a /16 to a /24
      iex> padr("255.255.0.0/16", 0, 8)
      "255.255.0.0/24"

      iex> padr("255.255.0.0/16", 1, 8)
      "255.255.255.0/24"

      iex> padr({{255, 255, 0, 0}, 16}, 1, 8)
      {{255, 255, 255, 0}, 24}

      # results are clipped to maxlen
      iex> padr("1.2.0.0/16", 1, 512)
      "1.2.255.255"

      iex> padr(%Pfx{bits: <<255, 255>>, maxlen: 32}, 0, 8)
      %Pfx{bits: <<255, 255, 0>>, maxlen: 32}

      iex> padr(%Pfx{bits: <<255, 255>>, maxlen: 32}, 1, 8)
      %Pfx{bits: <<255, 255, 255>>, maxlen: 32}

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

  def padr(pfx, bit, n) when is_integer(n) and n >= 0 and (bit === 0 or bit === 1) do
    new(pfx)
    |> padr(bit, n)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def padr(_, bit, n) when bit === 0 or bit === 1,
    do: raise(arg_error(:noneg, n))

  def padr(_, bit, _),
    do: raise(arg_error(:nobit, bit))

  @doc """
  Parses a `t:prefix/0` and returns `{:ok, Pfx.t}` or `{:error, :einvalid}`

  ## Examples

      iex> parse("1.2.3.4/24")
      {:ok, %Pfx{bits: <<1, 2, 3>>, maxlen: 32}}

      iex> parse({{1,2,3,4}, 24})
      {:ok, %Pfx{bits: <<1, 2, 3>>, maxlen: 32}}

      iex> parse({1,2,3,4})
      {:ok, %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}}

      iex> parse(%Pfx{bits: <<4, 3, 2, 1>>, maxlen: 32})
      {:ok, %Pfx{bits: <<4, 3, 2, 1>>, maxlen: 32}}

      iex> parse("1.2.3.4/33")
      {:error, :einvalid}

      iex> parse("acdc:1976::/32")
      {:ok, %Pfx{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128}}

      iex> parse("DEAD:BEER::/32")
      {:error, :einvalid}

  """
  @spec parse(prefix) :: {:ok, t()} | {:error, :einvalid}
  def parse(prefix) do
    {:ok, new(prefix)}
  rescue
    _ -> {:error, :einvalid}
  end

  @doc """
  Parses a `t:prefix/0` and returns `{:ok, Pfx.t}` or given `default` on error.

  Same as `Pfx.parse/1`, but returns given default on error.

  ## Examples

      iex> parse("0.0.0.0/32", :oops)
      {:ok, %Pfx{bits: <<0, 0, 0, 0>>, maxlen: 32}}

      iex> parse("0.0.0.0/33", :oops)
      :oops

      iex> pfx = "0.0.0.256/24"
      iex> parse(pfx, {:error, pfx})
      {:error, "0.0.0.256/24"}

      iex> parse("11:22:33:44:55:GG", {:error, :bad_eui48})
      {:error, :bad_eui48}

  """
  @spec parse(prefix, any) :: {:ok, t()} | any
  def parse(prefix, default) do
    case parse(prefix) do
      {:ok, prefix} -> {:ok, prefix}
      {:error, _} -> default
    end
  end

  @doc """
  Partitions `pfx` into a list of new prefixes, each `bitlen` long.

  Note that `bitlen` must be in the range of `bit_size(pfx.bits)..pfx.maxlen-1`.

  ## Examples

      # break out the /26's in a /24
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

      iex> partition(%Pfx{bits: <<10, 11, 12>>, maxlen: 32}, 26)
      [
        %Pfx{bits: <<10, 11, 12, 0::size(2)>>, maxlen: 32},
        %Pfx{bits: <<10, 11, 12, 1::size(2)>>, maxlen: 32},
        %Pfx{bits: <<10, 11, 12, 2::size(2)>>, maxlen: 32},
        %Pfx{bits: <<10, 11, 12, 3::size(2)>>, maxlen: 32}
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
    do: raise(arg_error(:nopart, bitlen))

  def partition(pfx, bitlen) do
    new(pfx)
    |> partition(bitlen)
    |> Enum.map(fn x -> marshall(x, pfx) end)
  rescue
    err -> raise err
  end

  @doc """
  Returns a list of prefixes that cover the given range of address space.

  The (inclusive) range can be specified either by:
  - `start`, `stop` prefixes, or
  - `start`, `nhosts`

  When using the `start`,`stop`-prefixes as a range, both prefixes need to be
  of the same type, otherwise an argument error is raised.  The second form of
  `start`, `nhosts` requires that `nhosts` does not exceed the addressable capacity
  of given `start` prefix's type.

  If `start` lies to the right of `stop`, they are *not* reversed and the build
  up of the list of prefixes will wrap around the available address space.
  If `nhosts` is negative, `start` is effectively the last address.

  Note: any mask information for `start` or `stop` prefixes are ignored, if
  possible.

  ## Examples

      iex> partition_range("10.10.10.0", "10.10.10.130")
      ["10.10.10.0/25", "10.10.10.128/31", "10.10.10.130"]
      iex> partition_range("10.10.10.0", 131)
      ["10.10.10.0/25", "10.10.10.128/31", "10.10.10.130"]

      iex> partition_range("10.10.10.0", 131)
      ...> |> Enum.map(&size/1) |> Enum.sum()
      131

      iex(481)> partition_range("acdc::1976", "acdc::2021")
      ["acdc:0:0:0:0:0:0:1976/127", "acdc:0:0:0:0:0:0:1978/125",
       "acdc:0:0:0:0:0:0:1980/121", "acdc:0:0:0:0:0:0:1a00/119",
       "acdc:0:0:0:0:0:0:1c00/118", "acdc:0:0:0:0:0:0:2000/123",
       "acdc:0:0:0:0:0:0:2020/127"]

  When working with address tuples, the result will be in addres,length-tuples otherwise
  prefix length information would be lost.

      # 128 hosts, starting with "10.10.10.128"
      iex> partition_range({10, 10, 10, 128}, 128)
      [{{10, 10, 10, 128}, 25}]

      # 1 host, starting with "10.10.10.10"
      iex> partition_range({10, 10, 10, 10}, 1)
      [{{10, 10, 10, 10}, 32}]

      # 0 hosts always yield an empty list
      iex> partition_range({10, 10, 10, 10}, 0)
      []
      iex> partition_range("10.10.10.10", 0)
      []

      # binary format may not show the /len, if it is a full prefix
      iex> partition_range("10.10.10.10", 1)
      ["10.10.10.10"]


  The range is inclusive, so both `start` and `stop` are always included.  In fact,
  `start` is the first address of the first prefix in the list and `stop` the last
  address in the last prefix.

      iex> partition_range("10.10.10.10", "10.10.10.10")
      ["10.10.10.10"]

      iex> partition_range("10.10.10.0", 512)
      ["10.10.10.0/23"]

      iex> partition_range("10.10.10.0", 131)
      ["10.10.10.0/25", "10.10.10.128/31", "10.10.10.130"]

      # negative number means start is actually the last address in the range
      iex> partition_range("10.10.10.130", -131)
      ["10.10.10.0/25", "10.10.10.128/31", "10.10.10.130"]

  Any mask information, if present, is ignored for both `start` and `stop`.  Note that
  when using `t:Pfx.t/0` structs, the mask will already have been applied in which case
  the address will be the first address in the prefix.

      iex> partition_range("10.10.10.8/24", 10)
      ["10.10.10.8/29", "10.10.10.16/31"]

      iex> partition_range("10.10.10.10/24", "10.10.10.17/24")
      ["10.10.10.10/31", "10.10.10.12/30", "10.10.10.16/31"]

      # Pfx.new() has already applied the mask
      iex> start = new("10.10.10.10/24")
      iex> stop = new("10.10.10.17/24")
      iex> partition_range(start, stop)
      [%Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32}]

      # so the above is basically the same as:
      iex> partition_range("10.10.10.0", "10.10.10.0")
      ["10.10.10.0"]

  The list of prefixes is built up starting with `start` and prefixes are added
  until it represents the entire range, wrapping the available address space if
  needed.  So if `start` actually lies to the right of `stop`, or if `nhosts`
  is large enough, wrapping may occur.  To avoid wrapping use `Pfx.compare/2`
  to check whether or not to swap `start` and `stop`.

      # happily wraps around address space boundary (so beware)
      iex> partition_range("0.0.0.0", -257)
      ["255.255.255.0/24", "0.0.0.0"]

      iex> partition_range("255.255.255.0", 257)
      ["255.255.255.0/24", "0.0.0.0"]

      iex> partition_range("255.255.255.255", "0.0.0.255")
      ["255.255.255.255", "0.0.0.0/24"]

      iex> start = "10.10.255.255"
      iex> stop = "10.10.0.0"
      iex> case compare(start, stop) do
      ...>   :gt -> partition_range(stop, start)
      ...>   _ -> partition_range(start, stop)
      ...> end
      ["10.10.0.0/16"]

  Finally, the list of prefixes will have varying prefix lengths that ramp up
  and down. So, when building some sort of access control list, sorting on
  prefix lengths (ascending, so less specifics come first) may be preferable.

      iex> partition_range("10.10.10.10", "10.10.10.31")
      ["10.10.10.10/31", "10.10.10.12/30", "10.10.10.16/28"]

      iex> partition_range("10.10.10.10", "10.10.10.31")
      ...> |> Enum.sort(&(pfxlen(&1) <= pfxlen(&2)))
      ["10.10.10.16/28", "10.10.10.12/30", "10.10.10.10/31"]

      # the above actually converts between string and `t:Pfx.t/0` twice,
      # to avoid that do something like this:
      iex> partition_range(new("10.10.10.10"), new("10.10.10.31"))
      ...> |> Enum.sort(&(pfxlen(&1) <= pfxlen(&2)))
      ...> |> Enum.map(&format/1)
      ["10.10.10.16/28", "10.10.10.12/30", "10.10.10.10/31"]

  """
  @spec partition_range(prefix, prefix | integer) :: [prefix]
  def partition_range(prefix, nhosts) when is_integer(nhosts) do
    addr = address(prefix) |> new()

    {addr, nhosts} =
      case nhosts < 0 do
        true ->
          {sibling(addr, nhosts + 1), -nhosts}

        _ ->
          {addr, nhosts}
      end

    unless nhosts <= trunc(:math.pow(2, addr.maxlen)),
      do: raise(arg_error(:nocapacity, "#{addr}, nhosts: #{nhosts}"))

    # so prefix length information is not lost (if prefix is address-tuple)
    format = if is_tuple(prefix), do: {{0, 0, 0, 0}, 0}, else: prefix

    partition_rangep(trim(addr), nhosts, [])
    |> Enum.map(fn x -> marshall(x, format) end)
  rescue
    error -> raise error
  end

  def partition_range(start, stop) do
    pfx_start = address(start) |> new()
    pfx_stop = address(stop) |> new()

    unless is_comparable(pfx_start, pfx_stop),
      do: raise(arg_error(:nocompare, {pfx_start, pfx_stop}))

    nstart = cast(pfx_start)
    nstop = cast(pfx_stop)

    nhosts =
      if nstart > nstop,
        do: 1 + trunc(:math.pow(2, pfx_start.maxlen)) - nstart + nstop,
        else: 1 + nstop - nstart

    partition_rangep(trim(pfx_start), nhosts, [])
    |> Enum.map(fn x -> marshall(x, start) end)
  rescue
    error -> raise error
  end

  @spec partition_rangep(Pfx.t(), non_neg_integer, [Pfx.t()]) :: [Pfx.t()]
  defp partition_rangep(_pfx, nhosts, acc) when nhosts < 1,
    do: Enum.reverse(acc)

  defp partition_rangep(pfx, 1, acc) do
    Enum.reverse([padr(pfx) | acc])
  end

  defp partition_rangep(pfx, nhosts, acc) do
    size = size(pfx)
    maxb = :math.log2(nhosts) |> trunc()

    cond do
      size == nhosts ->
        Enum.reverse([pfx | acc])

      size > nhosts ->
        pfx = padr(pfx, 0, pfx.maxlen - bit_size(pfx.bits) - maxb)
        size = size(pfx)
        next = sibling(pfx, 1) |> trim()
        partition_rangep(next, nhosts - size, [pfx | acc])

      size < nhosts ->
        nxt = sibling(pfx, 1) |> trim()
        partition_rangep(nxt, nhosts - size, [pfx | acc])
    end
  end

  @doc """
  Returns the length of the bitstring for given `prefix`.

  ## Examples

      iex> pfxlen("10.10.10.0/24")
      24

      iex> pfxlen({{10, 10, 10, 0}, 25})
      25

      iex> pfxlen(%Pfx{bits: <<10, 10, 10, 0::1>>, maxlen: 32})
      25

      iex> pfxlen("10.10.10.10")
      32
  """
  @spec pfxlen(prefix) :: non_neg_integer
  def pfxlen(prefix) do
    pfx = new(prefix)
    bit_size(pfx.bits)
  rescue
    err -> raise err
  end

  @doc """
  Removes `length` bits from `pfx`-s bitstring, starting at `position`.

  A negative `position` is relative to the end of the `pfx.bits`-string.
  Valid range for `position` is `-bit_size(pfx.bits) .. bit_size(pfx.bits)-1`.

  If `length` is positive, bits are removed to the right.  If it is negative
  bits are removed going to the left.

  Notes:
  - `length` is silently clipped to the maximum number of bits available to remove
  - removing bits from `pfx.bits` does not change its `pfx.maxlen`

  ## Examples

      # remove 2nd digit (2)
      iex> remove("1.2.3.4", 8, 8)
      "1.3.4.0/24"

      # remove 25th bit
      iex> remove("1.2.3.128/25", -1, 1)
      "1.2.3.0/24"

      # remove the FF.FE part
      iex> remove("0288.88FF.FE88.8888", 24, 16)
      "02-88-88-88-88-88-00-00/48"


      # remove 2nd digit (2)
      iex> remove({{1, 2, 3, 4}, 32}, 8, 8)
      {{1, 3, 4, 0}, 24}

  """
  @spec remove(prefix, non_neg_integer, non_neg_integer) :: prefix
  def remove(pfx, position, length)

  def remove(pfx, 0, 0) when is_pfx(pfx),
    do: pfx

  def remove(pfx, position, 0) when is_pfx(pfx) do
    bsize = bit_size(pfx.bits)

    pos =
      if position < 0,
        do: bsize + position,
        else: position

    if pos < 0 or pos >= bsize,
      do: raise(arg_error(:bitpos, position))

    pfx
  end

  def remove(pfx, position, length) when is_pfx(pfx) and is_integer(position * length) do
    bsize = bit_size(pfx.bits)
    # normalize position
    pos =
      if position < 0,
        do: bsize + position,
        else: position

    if pos < 0 or pos >= bsize,
      do: raise(arg_error(:range, {pfx, position, length}))

    {pos, len} =
      if length < 0,
        do: {pos + 1 + length, -length},
        else: {pos, length}

    # clip length to max bits available to remove
    {pos, len} =
      if pos < 0,
        do: {0, len + pos},
        else: {pos, len}

    {pos, len} =
      if pos + len > bsize,
        do: {pos, bsize - pos},
        else: {pos, len}

    <<left::bitstring-size(pos), _::bitstring-size(len), right::bitstring>> = pfx.bits

    %{pfx | bits: <<left::bitstring, right::bitstring>>}
  rescue
    err -> raise err
  end

  def remove(pfx, start, length) when is_integer(start * length) do
    new(pfx)
    |> remove(start, length)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def remove(_, start, length),
    do: raise(arg_error(:range, {start, length}))

  @doc """
  Returns another `Pfx` at distance `offset` from given `pfx`.

  This basically increases or decreases the number represented by the
  `pfx.bits` while keeping `pfx.maxlen` the same.

  Note that the length of `pfx.bits` will not change and cycling through
  all siblings will eventually wrap around.

  ## Examples

      iex> sibling("1.2.3.0/24", -1)
      "1.2.2.0/24"

      iex> sibling("0.0.0.0", -1)
      "255.255.255.255"

      iex> sibling({{1, 2, 3, 0}, 24}, 256)
      {{1, 3, 3, 0}, 24}

      iex> sibling(%Pfx{bits: <<10, 11>>, maxlen: 32}, 1)
      %Pfx{bits: <<10, 12>>, maxlen: 32}

      iex> sibling(%Pfx{bits: <<10, 11, 0>>, maxlen: 32}, 255)
      %Pfx{bits: <<10, 11, 255>>, maxlen: 32}

      # wraps around
      iex> sibling(%Pfx{bits: <<10, 11, 0>>, maxlen: 32}, 256)
      %Pfx{bits: <<10, 12, 0>>, maxlen: 32}

      iex> new(<<0, 0, 0, 0>>, 32) |> sibling(-1)
      %Pfx{bits: <<255, 255, 255, 255>>, maxlen: 32}

      # zero bit-length stays zero bit-length
      iex> sibling(%Pfx{bits: <<>>, maxlen: 0}, 1)
      %Pfx{bits: <<>>, maxlen: 0}


  """
  @spec sibling(prefix, integer) :: prefix
  def sibling(pfx, offset) when is_pfx(pfx) and is_integer(offset) do
    bsize = bit_size(pfx.bits)
    n = castp(pfx.bits, bit_size(pfx.bits))
    n = n + offset

    %Pfx{pfx | bits: <<n::size(bsize)>>}
  end

  def sibling(pfx, offset) when is_integer(offset) do
    new(pfx)
    |> sibling(offset)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def sibling(_, offset),
    do: raise(arg_error(:noint, offset))

  @doc """
  Returns the number of full addresses as represented by `pfx`.

  size(pfx) == 2^(pfx.maxlen - bit_size(pfx.bits))

  ## Examples

      iex> size("1.1.1.0/23")
      512

      iex> size({1,1,1,1})
      1

      iex> size({{1, 1, 1, 0}, 16})
      65536

      iex> size(%Pfx{bits: <<1, 1, 1>>, maxlen: 32})
      256

  """
  @spec size(prefix) :: pos_integer
  def size(pfx) when is_pfx(pfx) do
    :math.pow(2, pfx.maxlen - bit_size(pfx.bits)) |> trunc
  end

  def size(pfx) do
    new(pfx)
    |> size()
  rescue
    err -> raise err
  end

  @doc """
  Trims _all_ trailing `0`'s from given `prefix`.

  ## Examples

      iex> trim("255.255.255.0")
      "255.255.255.0/24"

      # perhaps more visible like thi
      iex> trim("255.255.255.0")
      ...> |> new()
      %Pfx{bits: <<255, 255, 255>>, maxlen: 32}

      iex> trim("10.10.128.0/30")
      "10.10.128.0/17"

      iex> trim({255, 255, 255, 0})
      {255, 255, 255, 0}
      iex> trim({{255, 255, 255, 0}, 32})
      {{255, 255, 255, 0}, 24}

      iex> trim("acdc:1976::ff00/128")
      "acdc:1976:0:0:0:0:0:ff00/120"

  """
  @spec trim(prefix) :: prefix
  def trim(prefix) do
    pfx = new(prefix)

    %{pfx | bits: trimp(pfx.bits)}
    |> marshall(prefix)
  rescue
    err -> raise err
  end

  defp trimp(<<>>),
    do: <<>>

  defp trimp(bits) do
    n = bit_size(bits) - 1
    <<rest::bitstring-size(n), bit::1>> = bits

    case bit do
      1 -> bits
      0 -> trimp(rest)
    end
  end

  @doc """
  Returns a `prefix` in the form of a tuple, with or without mask.

  The options include:
  - `:mask` whether to apply and include the mask (i.e. prefix length)
  - `:width` how many bits in an address part (default depends)

  The `:width` defaults to `8`, except when maxlen is 128, in which case it is `16`.
  These defaults are a good fit for IPv4, IPv6, EUI48 and EUI64 prefixes and produces
  a tuple representation that can easily be converted back into a `t:Pfx.t/0` struct
  if the need arises.

  ## Examples

      iex> to_tuple("1.1.1.0/24")
      {{1, 1, 1, 0}, 24}

      # mask is applied by default
      iex> to_tuple("1.1.1.12/24")
      {{1, 1, 1, 0}, 24}

      # unless :mask option is false
      iex> to_tuple("1.1.1.12/24", mask: false)
      {1, 1, 1, 12}

      # converts other formats of IPv4/6 and EUI48/64 as well
      iex> to_tuple({1, 1, 1, 12})
      {{1, 1, 1, 12}, 32}

      iex> to_tuple(%Pfx{bits: <<1, 1, 1, 12>>, maxlen: 32})
      {{1, 1, 1, 12}, 32}

      iex> to_tuple("acdc:1976::/32")
      {{0xacdc, 0x1976, 0, 0, 0, 0, 0, 0}, 32}

      # convert back
      iex> to_tuple("acdc:1976::/32")
      ...> |> new()
      %Pfx{bits: <<0xacdc::size(16), 0x1976::size(16)>>, maxlen: 128}

  For other types of prefixes, use the `:width` option to override how many bits
  go into an address part.  If the prefix has a maxlen that is not the number
  of address digits * their width, maxlen will need to be known when converting
  the tuple representation back into a `t:Pfx.t/0` struct (since it cannot be
  deduced).

      # maxlen is 30 bits, not 8*4
      iex> to_tuple(%Pfx{bits: <<0x12, 0x34, 0x56>>, maxlen: 30}, width: 4)
      {{1, 2, 3, 4, 5, 6, 0, 0}, 24}

      # conversion back into a Pfx struct requires `width` and `maxlen` to be known
      iex> pfx = %Pfx{bits: <<0x12, 0x34, 0x56>>, maxlen: 30}
      iex> {parts, pfxlen} = to_tuple(pfx, width: 4)
      iex> bits = for x <- Tuple.to_list(parts), into: <<>>, do: <<x::size(4)>>
      iex> new(bits, 30)
      ...> |> keep(pfxlen)
      %Pfx{bits: <<0x12, 0x34, 0x56>>, maxlen: 30}

      # or less convoluted
      iex> pfx = %Pfx{bits: <<0x12, 0x34, 0x56>>, maxlen: 30}
      iex> to_tuple(pfx, width: 4)
      ...> |> undigits(4)
      ...> |> new(30)
      %Pfx{bits: <<0x12, 0x34, 0x56>>, maxlen: 30}

  """
  @spec to_tuple(prefix, Keyword.t()) :: tuple
  def to_tuple(prefix, opts \\ []) do
    mask = Keyword.get(opts, :mask, true)
    pfx = if mask, do: new(prefix), else: address(prefix) |> new()
    width = if pfx.maxlen == 128, do: 16, else: 8
    width = Keyword.get(opts, :width, width)
    digits = digits(pfx, width)

    if mask,
      do: digits,
      else: elem(digits, 0)
  rescue
    error -> raise error
  end

  @doc """
  Returns the prefix type, one of `:ip4`, `:ip6`, `:eui48`, `eui64` or simply
  its maxlen property.

  ## Examples

      iex> type("1.2.3.4")
      :ip4
      iex> type("1.2.3.0/24")
      :ip4
      iex> type({1, 2, 3, 4})
      :ip4
      iex> type({{1, 2, 3, 4}, 24})
      :ip4
      iex> type(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32})
      :ip4

      iex> type("acdc:1976::1")
      :ip6
      iex> type({1, 2, 3, 4, 5, 6, 7, 8})
      :ip6
      iex> type({{1, 2, 3,4 ,5 ,6, 7, 8}, 64})
      :ip6
      iex> type(%Pfx{bits: <<>>, maxlen: 128})
      :ip6

      iex> type("aa-bb-cc-dd-ee-ff")
      :eui48
      iex> type(%Pfx{bits: <<0xaa, 0xbb>>, maxlen: 48})
      :eui48

      iex> type("aa-bb-cc-ee-ff-00-00-00")
      :eui64
      iex> type(%Pfx{bits: <<0xaa, 0xbb, 0xcc>>, maxlen: 64})
      :eui64

      iex> type(%Pfx{bits: <<1, 2>>, maxlen: 256})
      256

  """
  @spec type(prefix) :: :ip4 | :ip6 | :eui48 | :eui64 | non_neg_integer()
  def type(prefix) do
    case new(prefix).maxlen do
      32 -> :ip4
      48 -> :eui48
      64 -> :eui64
      128 -> :ip6
      n -> n
    end
  rescue
    _ -> :einvalid
  end

  @doc """
  Returns the prefix represented by the `digits`, actual `length` and a given
  field `width`.

  The `pfx.bits` are formed by first concatenating the `digits` expressed as
  bitstrings of `width`-bits wide and then truncating to `length` bits.

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

      # 32 4-bit wide numbers turn into an IPv6 prefix, truncated to 32 bits
      # and maxlen is set to 32 * 4 = 128
      iex> undigits({{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 32},4)
      %Pfx{bits: <<0x12, 0x34, 0x56, 0x78>>, maxlen: 128}

  """
  @spec undigits({tuple(), pos_integer}, pos_integer) :: t()
  def undigits({digits, length}, width)
      when is_pos_integer(width) and is_non_neg_integer(length) do
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

  def undigits({_digits, length}, width) when is_pos_integer(width),
    do: raise(arg_error(:noneg, length))

  def undigits({_digits, _length}, width),
    do: raise(arg_error(:nopos, width))

  def undigits(digits, _),
    do: raise(arg_error(:noundig, digits))

  @doc """
  Returns a boolean indicating whether `pfx` is a valid `t:prefix/0` or not.

  ## Examples

      iex> valid?("1.2.3.4")
      true

      iex> valid?("1.2.3.4/8")
      true

      iex> valid?({1, 2, 3, 4})
      true

      iex> valid?({{1, 2, 3, 4}, 24})
      true

      iex> valid?(%Pfx{bits: <<1,2,3,4>>, maxlen: 32})
      true

      # bits exceed maxlen
      iex> valid?(%Pfx{bits: <<1,2,3,4>>, maxlen: 16})
      false

  """
  @spec valid?(prefix) :: boolean
  def valid?(prefix) do
    new(prefix)
    true
  rescue
    _ -> false
  end

  # IP oriented

  @doc """
  Returns the broadcast prefix (full address) for given `pfx`.

  Yields the same result as `Pfx.last/1`, included for nostalgia.

  ## Examples

      iex> broadcast("10.10.0.0/16")
      "10.10.255.255"

      # a full address is its own broadcast address
      iex> broadcast({10, 10, 10, 1})
      {10, 10, 10, 1}

      iex> broadcast({{10, 10, 10, 1}, 30})
      {{10, 10, 10, 3}, 32}

      iex> broadcast(%Pfx{bits: <<10, 10, 10>>, maxlen: 32})
      %Pfx{bits: <<10, 10, 10, 255>>, maxlen: 32}

      iex> broadcast(%Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128})
      %Pfx{bits: <<0xACDC::16, 0x1976::16, -1::96>>, maxlen: 128}

      iex> broadcast("acdc:1976::/112")
      "acdc:1976:0:0:0:0:0:ffff"

  """
  @doc section: :ip
  @spec broadcast(prefix) :: prefix
  def broadcast(pfx) do
    last(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Returns a reverse DNS name (pointer) for given `pfx`.

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

      iex> dns_ptr("acdc:1975::b1ba:2021")
      "1.2.0.2.a.b.1.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.7.9.1.c.d.c.a.ip6.arpa"

  """
  @doc section: :ip
  @spec dns_ptr(prefix) :: String.t()
  def dns_ptr(pfx) do
    x = new(pfx)
    if bit_size(x.bits) == 0, do: raise(arg_error(:nobits, pfx))

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
  rescue
    err -> raise err
  end

  @doc """
  Creates a modified EUI-64 out of `eui` (an EUI-48 address or an EUI-64).

  This flips the 7-th bit (U/L - universal/local) and inserts `0xFFFE` in the
  middle.

  The function assumes either an EUI-48 or EUI-64 address.  In the latter case,
  it'll only flip the 7-th bit.

  ## Examples

      iex> eui64_encode("0088.8888.8888")
      "02-88-88-FF-FE-88-88-88"

      iex> eui64_encode("0288.8888.8888")
      "00-88-88-FF-FE-88-88-88"

      iex> eui64_encode({0x00, 0x88, 0x88, 0x88, 0x88, 0x88})
      {0x02, 0x88, 0x88, 0xFF, 0xFE, 0x88, 0x88, 0x88}

      # modified EUI-64 from an existing EUI-64, simply flip the 7th bit
      iex> eui64_encode("01:23:45:67:89:AB:CD:EF")
      "03-23-45-67-89-AB-CD-EF"


  """
  @doc section: :ip
  @spec eui64_encode(prefix) :: prefix
  def eui64_encode(eui)
      when is_pfx(eui) and eui.maxlen == 48 and bit_size(eui.bits) == 48 do
    eui
    |> new(64)
    |> insert(<<0xFF, 0xFE>>, 24)
    |> flip(6)
  end

  def eui64_encode(eui)
      when is_pfx(eui) and eui.maxlen == 64 and bit_size(eui.bits) == 64 do
    flip(eui, 6)
  end

  def eui64_encode(pfx) do
    # if pfx is a pfx, its not an eui48 nor eui64 and from_mac will raise
    # an ArgumentError
    from_mac(pfx)
    |> eui64_encode()
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Decodes a modified EUI-64 back into the original EUI-48 address.

  This function flips the 7-th bit and removes 16-bits from the middle.
  Those 16-bits should be `0xFFFE`, but this is not checked or enforced.

  ## Examples

      iex> eui64_decode("0088.88FE.FF88.8888")
      "02-88-88-88-88-88"

      iex> eui64_decode("0288.88FF.FE88.8888")
      "00-88-88-88-88-88"

      iex> eui64_decode("02-88-88-FF-FE-88-88-88")
      "00-88-88-88-88-88"

      iex> eui64_decode({0x02, 0x88, 0x88, 0xFF, 0xFE, 0x88, 0x88, 0x88})
      {0x00, 0x88, 0x88, 0x88, 0x88, 0x88}

      iex> new("2001:db8:1:2:020c:29ff:fe0c:47d5")
      ...> |> cut(-1, -64)
      ...> |> eui64_decode()
      ...> |> format()
      "00-0C-29-0C-47-D5"

  """
  @doc section: :ip
  @spec eui64_decode(prefix) :: prefix
  def eui64_decode(pfx) when is_pfx(pfx) do
    unless bit_size(pfx.bits) == 64,
      do: raise(arg_error(:noeui64, pfx))

    pfx
    |> flip(6)
    |> remove(24, 16)
    |> new(48)
  end

  def eui64_decode(pfx) do
    from_mac(pfx)
    |> eui64_decode()
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Returns a map with link-local address components for given `pfx`.

  Returns nil if `pfx` is not link-local as per
  [rfc3927](https://www.iana.org/go/rfc3927) or
  [rfc4291](https://www.rfc-editor.org/rfc/rfc4291)

  ## Examples

      iex> x = link_local("169.254.128.233")
      iex> x
      %{ digits: {169, 254, 128, 233},
         prefix: "169.254.0.0/16",
         ifaceID: 33001,
         address: "169.254.128.233"
      }
      #
      iex> host(x.prefix, x.ifaceID)
      "169.254.128.233"

      iex> y = link_local("fe80::acdc:1976")
      iex> y
      %{ preamble: 1018,
         prefix: "fe80:0:0:0:0:0:0:0/64",
         ifaceID: 2900105590,
         address: "fe80::acdc:1976"
      }
      #
      iex> host(y.prefix, y.ifaceID)
      "fe80:0:0:0:0:0:acdc:1976"

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
            prefix: keep(x, 64) |> marshall(pfx),
            ifaceID: cut(x, 64, 64) |> cast(),
            address: pfx
          }

        32 ->
          %{
            digits: digits(x, 8) |> elem(0),
            prefix: keep(x, 16) |> marshall(pfx),
            ifaceID: cut(x, 16, 16) |> cast(),
            address: pfx
          }
      end
    else
      nil
    end
  rescue
    err -> raise err
  end

  @doc """
  Returns true if `pfx` is a link-local prefix, false otherwise

  Link local prefixes include:

  - `0.0.0.0/8`,          [rfc1122](https://tools.ietf.org/html/rfc1122), 'this-network'
  - `255.255.255.255/32`, [rfc1f22](https://www.iana.org/go/rfc1122), limited broadcast
  - `169.254.0.0/16`,     [rfc3927](https://www.iana.org/go/rfc3927), link-local (see examples)
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

      iex> link_local?("fe80::acdc:1975")
      true

      iex> link_local?("1.1.1.1")
      false

      # bad prefix
      iex> link_local?("10.10.10.256")
      false

  """
  @doc section: :ip
  @spec link_local?(prefix) :: boolean
  def link_local?(pfx) do
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
  rescue
    _ -> false
  end

  @doc """
  Returns true is `pfx` is a multicast prefix, false otherwise

  Checks if `pfx` given is a member of:
  - `224.0.0.0/4` [rfc1112](https://www.rfc-editor.org/rfc/rfc1112.html).
  - `ff00:/8` [rfc4921](https://www.rfc-editor.org/rfc/rfc4291.html)

  ## Examples

      iex> multicast?("224.0.0.1")
      true

      iex> multicast?("ff02::1")
      true

      iex> multicast?({{224, 0, 0, 1}, 32})
      true

      iex> multicast?({224, 0, 0, 1})
      true

      iex> multicast?(%Pfx{bits: <<224, 0, 0, 1>>, maxlen: 32})
      true

      iex> multicast?("1.1.1.1")
      false

      # bad prefix
      iex> multicast?("224.0.0.256")
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
  rescue
    _ -> false
  end

  @doc """
  Returns a map with multicast address components for given `pfx`.

  Address components are parsed according to:
  - [rfc1112](https://www.rfc-editor.org/rfc/rfc1112.html) -
    Host Extensions for IP Multicasting
  - [rfc4291](https://www.rfc-editor.org/rfc/rfc4291.html) -
    IP Version 6 Addressing Architecture

  Rfc specific fields are put in their own map under the `rfc`-key.
  - [rfc6034](https://www.rfc-editor.org/rfc/rfc6034.html) -
    Unicast-Prefix-Based IPv4 Multicast Addresses
  - [rfc3180](https://www.rfc-editor.org/rfc/rfc3180) -
    GLOP Addressing in 233/8
  - [rfc3956](https://www.rfc-editor.org/rfc/rfc3956) -
    Embedding the Rendezvous Point (RP) Address in an IPv6 Multicast Address
  - [rfc3306](https://www.rfc-editor.org/rfc/rfc3306) -
    Unicast-Prefix-based IPv6 Multicast Addresses

  Note that for unicast-prefix-based IPv4 multicast addresses, the unicast
  prefix is always taken to be 24 bits long.  That should still allow for
  identification of the origin by looking up the assigned unicast address space
  that includes the /24.

  ## Examples

      iex> multicast_decode("234.192.0.2")
      %{
        multicast_address: "234.192.0.2",
        protocol: :ipv4,
        rfc: %{
          group_id: 2,
          multicast_prefix: "234.0.0.0/8",
          rfc: 6034,
          unicast_prefix: "192.0.2.0/24"
        }
      }

      iex> Pfx.multicast_decode("FF32:0030:3FFE:FFFF:0001::/96")
      %{
        flags: {0, 0, 1, 1},
        multicast_address: "ff32:30:3ffe:ffff:1:0:0:0/96",
        multicast_prefix: "ff30:0:0:0:0:0:0:0/12",
        protocol: :ipv6,
        rfc: %{
          group_id: 0,
          unicast_prefix: "3ffe:ffff:1:0:0:0:0:0/48",
          plen: 48,
          reserved: 0,
          rfc: 3306
        },
        scope: 2
      }
  """
  @doc section: :ip
  @spec multicast_decode(prefix) :: map | nil
  def multicast_decode(pfx) do
    x = new(pfx)

    if multicast?(x) do
      case x.maxlen do
        128 -> multicast_decode_ip6(x, pfx)
        32 -> multicast_decode_ip4(x, pfx)
      end
    else
      nil
    end
  rescue
    err -> raise err
  end

  @spec multicast_decode_ip6(t(), prefix) :: map
  defp multicast_decode_ip6(x, pfx) do
    flags = cut(x, 8, 4) |> digits(1) |> elem(0)

    generic = %{
      multicast_address: marshall(x, pfx),
      multicast_prefix: keep(x, 12) |> marshall(pfx),
      flags: flags,
      scope: cut(x, 12, 4) |> cast(),
      protocol: :ipv6
    }

    specific =
      case flags do
        {0, 0, 1, 1} ->
          plen = cut(x, 24, 8) |> cast()

          %{
            rfc: 3306,
            plen: plen,
            reserved: cut(x, 16, 8) |> cast(),
            unicast_prefix: cut(x, 32, 64) |> keep(plen) |> new(128) |> marshall(pfx),
            group_id: cut(x, -1, -32) |> cast()
          }

        {0, 1, 1, 1} ->
          plen = cut(x, 24, 8) |> cast()
          rrid = cut(x, 20, 4) |> cast()
          net_pfx = cut(x, 32, 64) |> keep(plen) |> new(128)

          %{
            rfc: 3956,
            plen: plen,
            reserved: cut(x, 16, 4) |> cast(),
            unicast_prefix: marshall(net_pfx, pfx),
            group_id: cut(x, -1, -32) |> cast(),
            riid: rrid,
            rp_prefix: padr(net_pfx) |> insert(<<rrid::4>>, -4) |> marshall(pfx)
          }

        _ ->
          %{
            rfc: 4291,
            group_id: cut(x, 16, 112) |> cast()
          }
      end

    Map.put(generic, :rfc, specific)
  end

  @spec multicast_decode_ip4(t(), prefix) :: map
  defp multicast_decode_ip4(x, pfx) do
    byte0 = cut(x, 0, 8) |> cast()

    generic = %{
      multicast_address: marshall(x, pfx),
      protocol: :ipv4
    }

    specific =
      case byte0 do
        233 ->
          %{
            rfc: 3180,
            as: cut(x, 8, 16) |> cast(),
            local_bits: cut(x, 24, 8) |> cast(),
            multicast_prefix: keep(x, 8) |> marshall(pfx)
          }

        234 ->
          %{
            rfc: 6034,
            unicast_prefix: cut(x, 8, 24) |> new(32) |> marshall(pfx),
            group_id: cut(x, 24, 8) |> cast(),
            multicast_prefix: keep(x, 8) |> marshall(pfx)
          }

        _ ->
          %{
            multicast_prefix: keep(x, 4) |> marshall(pfx),
            rfc: 1112
          }
      end

    Map.put(generic, :rfc, specific)
  end

  @doc """
  Returns true if `pfx` is matched by the Well-Known Prefixes defined in
  [rfc6053](https://www.iana.org/go/rfc6052) and
  [rfc8215](https://www.iana.org/go/rfc8215), false otherwise.

  Note that organisation specific prefixes might still be used for nat64.

  ## Examples

      iex> nat64?("64:ff9b::10.10.10.10")
      true

      iex> nat64?("64:ff9b:1::10.10.10.10")
      true

      iex> nat64?({{0x64, 0xff9b, 0, 0, 0, 0, 0x1010, 0x1010}, 128})
      true

      iex> nat64?({0x64, 0xff9b, 0, 0, 0, 0, 0x1010, 0x1010})
      true

      iex> nat64?(%Pfx{bits: <<0x64::16, 0xff9b::16, 0::64, 0x1010::16, 0x1010::16>>, maxlen: 128})
      true

      # illegal/bad prefix
      iex> nat64?("64:ff9b:1::10.10.10.256")
      false

  """
  @doc section: :ip
  @spec nat64?(prefix) :: boolean
  def nat64?(pfx) do
    x = new(pfx)

    member?(x, %Pfx{bits: <<0x64::16, 0xFF9B::16, 0::64>>, maxlen: 128}) or
      member?(x, %Pfx{bits: <<0x64::16, 0xFF9B::16, 1::16>>, maxlen: 128})
  rescue
    _ -> false
  end

  @doc """
  Returns the embedded IPv4 address of a nat64 `pfx`

  The `pfx` prefix should be a full IPv6 address.  The `len` defaults to `96`,
  but if specified it should be one of [#{Enum.join(@nat64_lengths, ", ")}].

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

      iex> nat64_decode({0x2001, 0xdb8, 0x122, 0x344, 0xC0, 0x2, 0x2100, 0x0}, 64)
      {192, 0, 2, 33}

      iex> nat64_decode({{0x2001, 0xdb8, 0x122, 0x344, 0xC0, 0x2, 0x2100, 0x0}, 128}, 64)
      {{192, 0, 2, 33}, 32}

      iex> nat64_decode("2001:db8:122:344::192.0.2.33", 96)
      "192.0.2.33"

      iex> nat64_decode("2001:db8:122:344::192.0.2.33", 90)
      ** (ArgumentError) nat64 prefix length not in [96, 64, 56, 48, 40, 32], got 90

  """
  @doc section: :ip
  @spec nat64_decode(prefix, integer) :: prefix
  def nat64_decode(pfx, len \\ 96)

  def nat64_decode(pfx, len) when is_pfx(pfx) and len in @nat64_lengths do
    unless pfx.maxlen == 128,
      do: raise(arg_error(:pfx6, "#{pfx}"))

    unless bit_size(pfx.bits) == 128,
      do: raise(arg_error(:pfx6full, "#{pfx}"))

    pfx = if len < 96, do: remove(pfx, 64, 8), else: pfx
    %Pfx{bits: bits(pfx, len, 32), maxlen: 32}
  rescue
    err -> raise err
  end

  def nat64_decode(pfx, len) when len in @nat64_lengths do
    new(pfx)
    |> nat64_decode(len)
    |> marshall(pfx)
  rescue
    err -> raise err
  end

  def nat64_decode(_, len),
    do: raise(arg_error(:nat64len, len))

  @doc """
  Returns an IPv4 embedded IPv6 address for given `pfx6` and `pfx4`.

  The length of the `pfx6.bits` should be one of [#{Enum.join(@nat64_lengths, ", ")}] as defined
  in [rfc6052](https://www.iana.org/go/rfc6052).  The `pfx4` prefix should be a full address.

  ## Examples

      iex> nat64_encode("2001:db8:100::/40", "192.0.2.33")
      "2001:db8:1c0:2:21:0:0:0"

      iex> nat64_encode("2001:db8:122::/48", "192.0.2.33")
      "2001:db8:122:c000:2:2100:0:0"

      iex> nat64_encode("2001:db8:122:300::/56", "192.0.2.33")
      "2001:db8:122:3c0:0:221:0:0"

      iex> nat64_encode("2001:db8:122:344::/64", "192.0.2.33")
      "2001:db8:122:344:c0:2:2100:0"

      iex> nat64_encode("2001:db8:122:344::/96", "192.0.2.33")
      "2001:db8:122:344:0:0:c000:221"

      iex> nat64_encode({{0x2001, 0xdb8, 0, 0, 0, 0, 0, 0}, 32}, "192.0.2.33")
      {{0x2001, 0xdb8, 0xc000, 0x221, 0, 0, 0, 0}, 128}

      iex> nat64_encode(%Pfx{bits: <<0x2001::16, 0xdb8::16>>, maxlen: 128}, "192.0.2.33")
      %Pfx{bits: <<0x2001::16, 0xdb8::16, 0xc000::16, 0x221::16, 0::64>>, maxlen: 128}

      iex> nat64_encode("2001:db8::/32", "192.0.2.33")
      "2001:db8:c000:221:0:0:0:0"

  """
  @doc section: :ip
  @spec nat64_encode(prefix(), prefix()) :: prefix
  def nat64_encode(pfx6, pfx4) when is_pfx(pfx6) do
    unless bit_size(pfx6.bits) in @nat64_lengths,
      do: raise(arg_error(:nat64, pfx6))

    ip4 = new(pfx4)

    unless bit_size(ip4.bits) == 32,
      do: raise(arg_error(:pfx4, pfx4))

    pfx6 = %{pfx6 | bits: pfx6.bits <> ip4.bits}

    if bit_size(pfx6.bits) < 128 do
      insert(pfx6, <<0>>, 64)
      |> padr(0)
    else
      pfx6
    end
  rescue
    err -> raise err
  end

  def nat64_encode(pfx6, pfx4) do
    new(pfx6)
    |> nat64_encode(pfx4)
    |> marshall(pfx6)
  rescue
    err -> raise err
  end

  @doc """
  Returns the this-network prefix (full address) for given `pfx`.

  Yields the same result as `Pfx.first/1`, included for nostalgia.

  ## Examples

      iex> network("10.10.10.1/24")
      "10.10.10.0"

      iex> network("acdc:1976::/32")
      "acdc:1976:0:0:0:0:0:0"

      # a full address is its own this-network
      iex> network({10, 10, 10, 1})
      {10, 10, 10, 1}

      iex> network({{10, 10, 10, 1}, 24})
      {{10, 10, 10, 0}, 32}

      iex> network(%Pfx{bits: <<10, 10, 10>>, maxlen: 32})
      %Pfx{bits: <<10, 10, 10, 0>>, maxlen: 32}

      iex> network(%Pfx{bits: <<0xacdc::16, 0x1976::16>>, maxlen: 128})
      %Pfx{bits: <<0xACDC::16, 0x1976::16, 0::96>>, maxlen: 128}

  """
  @doc section: :ip
  @spec network(prefix) :: prefix
  def network(pfx) do
    first(pfx)
  rescue
    err -> raise err
  end

  @doc """
  Returns true if given `pfx` is a teredo address, false otherwise

  IPv6 address within the teredo service prefix of `2000:0::/32`

  More details in [rfc4380](https://www.iana.org/go/rfc4380).

  ## Examples

      iex> teredo?("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
      true

      iex> teredo?("1.1.1.1")
      false

      iex> teredo?(42)
      false

  """
  @doc section: :ip
  @spec teredo?(prefix) :: boolean
  def teredo?(pfx) do
    new(pfx)
    |> member?(%Pfx{bits: <<0x2001::16, 0::16>>, maxlen: 128})
  rescue
    _ -> false
  end

  @doc """
  Returns a map with the teredo address components of `pfx` or nil.

  Returns nil if `pfx` is not a
  [teredo](https://www.rfc-editor.org/rfc/rfc4380.html#section-4) address.

  A teredo address consists of:
  1. the teredo service prefix of `2000:0::/32`
  2. IPv4 address of the teredo server
  3. flags (16 bits) that document type of address and NAT
  4. Port (16 bits), the obfuscated "mapped UDP port" at the client
  5. IPv4 address (obfucated) of the teredo client.

  More details in [rfc4380](https://www.iana.org/go/rfc4380).

  ## Examples

      # example from https://en.wikipedia.org/wiki/Teredo_tunneling#IPv6_addressing
      iex> teredo_decode("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
      %{
        server: "65.54.227.120",
        client: "192.0.2.45",
        port: 40000,
        flags: {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        prefix: "2001:0000:4136:e378:8000:63bf:3fff:fdd2"
      }

      iex> teredo_decode({0x2001, 0, 0x4136, 0xe378, 0x8000, 0x63bf, 0x3fff, 0xfdd2})
      %{
        server: {65, 54, 227, 120},
        client: {192, 0, 2, 45},
        port: 40000,
        flags: {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        prefix: {0x2001, 0x0, 0x4136, 0xe378, 0x8000, 0x63bf, 0x3fff, 0xfdd2}
      }

      iex> teredo_decode("1.1.1.1")
      nil

  """
  @doc section: :ip
  @spec teredo_decode(prefix) :: map | nil
  def teredo_decode(pfx) do
    x = new(pfx)

    if teredo?(x) do
      %{
        server: cut(x, 32, 32) |> marshall(pfx),
        client: cut(x, 96, 32) |> bnot() |> marshall(pfx),
        port: cut(x, 80, 16) |> bnot() |> cast(),
        flags: cut(x, 64, 16) |> digits(1) |> elem(0),
        prefix: pfx
      }
    else
      nil
    end
  rescue
    err -> raise err
  end

  @doc """
  Encodes given `server`, `client`, `port` and `flags` as an IPv6 teredo address.

  The `client` and `server` must be full IPv4 adresses, while both `port` and `flags`
  are interpreted as 16-bit unsigned integers.

  The result mirrors the representation format of the `client` argument.

  ## Examples

      iex> flags = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
      iex> teredo_encode("192.0.2.45", "65.54.227.120", 40000, flags)
      "2001:0:4136:e378:8000:63bf:3fff:fdd2"

      iex> flags = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
      iex> teredo_encode({192, 0, 2, 45}, "65.54.227.120", 40000, flags)
      {0x2001, 0, 0x4136, 0xe378, 0x8000, 0x63bf, 0x3fff, 0xfdd2}

      iex> flags = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
      iex> teredo_encode({{192, 0, 2, 45}, 32}, "65.54.227.120", 40000, flags)
      {{0x2001, 0, 0x4136, 0xe378, 0x8000, 0x63bf, 0x3fff, 0xfdd2}, 128}

      iex> flags = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
      iex> teredo_encode(%Pfx{bits: <<192, 0, 2, 45>>, maxlen: 32}, "65.54.227.120", 40000, flags)
      %Pfx{bits: <<0x2001::16, 0::16, 0x4136::16, 0xe378::16, 0x8000::16, 0x63bf::16, 0x3fff::16, 0xfdd2::16>>, maxlen: 128}

  """
  @doc section: :ip
  @spec teredo_encode(prefix, prefix, integer, tuple) :: prefix
  def teredo_encode(client, server, port, flags)
      when is_integer(port) and tuple_size(flags) == 16 do
    c = new(client) |> bnot()
    s = new(server)

    if bit_size(c.bits) != 32 or c.maxlen != 32,
      do: raise(arg_error(:pfx4full, client))

    if bit_size(s.bits) != 32 or s.maxlen != 32,
      do: raise(arg_error(:pfx4full, server))

    p = <<Bitwise.bnot(port)::16>>
    f = undigits({flags, 16}, 1)

    x = %Pfx{
      bits: <<0x20010000::32, s.bits::bits, f.bits::bits, p::bits, c.bits::bits>>,
      maxlen: 128
    }

    marshall(x, client)
  rescue
    err -> raise err
  end

  def teredo_encode(_client, _server, port, flags) when tuple_size(flags) == 16,
    do: raise(arg_error(:noint, port))

  def teredo_encode(_client, _server, port, flags) when is_integer(port),
    do: raise(arg_error(:noflags, flags))

  @doc """
  Returns true if `pfx` is designated as "private-use".

  This includes the [rfc1918](https://www.iana.org/go/rfc1918) prefixes:
  - `10.0.0.0/8`,
  - `172.16.0.0/12`, and
  - `192.168.0.0/16`.

  And the [rfc4193](https://www.iana.org/go/rfc4193) prefix
  - `fc00::/7`.

  ## Examples

      iex> unique_local?("172.31.255.255")
      true

      iex> unique_local?("10.10.10.10")
      true

      iex> unique_local?("fc00:acdc::")
      true

      iex> unique_local?("172.32.0.0")
      false

      iex> unique_local?("10.255.255.255")
      true

      iex> unique_local?({{172, 31, 255, 255}, 32})
      true

      iex> unique_local?({172, 31, 255, 255})
      true

      iex> unique_local?(%Pfx{bits: <<172, 31, 255, 255>>, maxlen: 32})
      true

      # bad prefix
      iex> unique_local?("10.255.255.256")
      false

  """
  @doc section: :ip
  @spec unique_local?(prefix) :: boolean
  def unique_local?(pfx) do
    x = new(pfx)

    cond do
      member?(x, %Pfx{bits: <<10>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<172, 1::4>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<192, 168>>, maxlen: 32}) -> true
      member?(x, %Pfx{bits: <<126::7>>, maxlen: 128}) -> true
      true -> false
    end
  rescue
    _ -> false
  end
end

defimpl String.Chars, for: Pfx do
  def to_string(pfx) do
    # delegates to Pfx.format with maxlen specific options, but should *NEVER*
    # delegate to Pfx.format without at least 1 option!
    case pfx.maxlen do
      32 -> Pfx.format(pfx, base: 10, width: 8, unit: 1, ssep: ".")
      48 -> Pfx.format(pfx, base: 16, width: 4, unit: 2, ssep: "-")
      64 -> Pfx.format(pfx, base: 16, width: 4, unit: 2, ssep: "-")
      128 -> Pfx.format(pfx, base: 16, width: 16, unit: 1, ssep: ":") |> String.downcase()
      _ -> Pfx.format(pfx, ssep: ".")
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
    {:ok, size, fn start, len -> slicep(pfx, start, len) end}
  end

  @spec slicep(Pfx.t(), non_neg_integer, pos_integer) :: [Pfx.t()]
  defp slicep(pfx, start, len) do
    for pos <- start..(start + len - 1) do
      Pfx.member(pfx, pos)
    end
  end

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
