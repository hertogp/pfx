defmodule PfxTest do
  use ExUnit.Case
  doctest Pfx, import: true
  import Pfx

  @bad_representations [
    %Pfx{bits: <<255>>, maxlen: 7},
    %Pfx{bits: <<255>>, maxlen: -7},
    %Pfx{bits: <<255>>, maxlen: 8.0},
    %Pfx{bits: '255', maxlen: 0},
    "1.1.1.256",
    "1.1.1.256/24",
    "1.2.3.4/33",
    {1, 2, 3, 256},
    {{1, 2, 3, 256}, 24},
    {{1, 2, 3, 4}, 33},
    "a:b:c:d:e:f:g::",
    "a:b:c:d:e:f::/129",
    {0, 0, 0, 0, 0, 0, 0, 655_356},
    {{0, 0, 0, 0, 0, 0, 0, 655_356}, 112},
    {{0, 0, 0, 0, 0, 0, 0, 0}, 129}
  ]

  @ip4_representations [
    %Pfx{bits: <<>>, maxlen: 32},
    "0.0.0.0/0",
    {{0, 0, 0, 0}, 0},
    {{0, 0, 0, 0}, nil},
    %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32},
    "1.2.3.4",
    {1, 2, 3, 4},
    {{1, 2, 3, 4}, 32},
    %Pfx{bits: <<1, 2, 3, 0::1>>, maxlen: 32},
    "1.2.3.0/25",
    {{1, 2, 3, 0}, 25}
  ]

  @ip6_representations [
    %Pfx{bits: <<>>, maxlen: 128},
    "::",
    "::/0",
    {{0, 0, 0, 0, 0, 0, 0, 0}, 0},
    {{0, 0, 0, 0, 0, 0, 0, 0}, nil},
    %Pfx{bits: <<1::16, 2::16, 3::16, 4::16>>, maxlen: 128},
    "1:2:3:4::/68",
    {1, 2, 3, 4, 0, 0, 0, 0},
    {{1, 2, 3, 4, 0, 0, 0, 0}, 65},
    %Pfx{bits: <<1::16, 2::16, 3::16, 4::16, 0::1>>, maxlen: 128},
    "1:2:3:4:0::/65",
    {{1, 2, 3, 4, 0, 0, 0, 0}, 65}
  ]

  # Guard

  # Is_pfx/1
  test "is_pfx/1" do
    # handle zero bits
    assert is_pfx(%Pfx{bits: <<>>, maxlen: 0})
    assert is_pfx(%Pfx{bits: <<>>, maxlen: 10000})

    # handle 1 bit
    assert is_pfx(%Pfx{bits: <<0::1>>, maxlen: 1})
    assert is_pfx(%Pfx{bits: <<1::1>>, maxlen: 1})

    # handle more bits
    assert is_pfx(%Pfx{bits: <<0::7>>, maxlen: 8})
    assert is_pfx(%Pfx{bits: <<0>>, maxlen: 8})
    assert is_pfx(%Pfx{bits: <<0::512>>, maxlen: 512})

    # maxlen not non_neg_integer
    refute is_pfx(%Pfx{bits: <<>>, maxlen: -1})
    refute is_pfx(%Pfx{bits: <<>>, maxlen: 0.0})

    # more bits than maxlen allows
    refute is_pfx(%Pfx{bits: <<255>>, maxlen: 7})

    # bits not a bitstring
    refute is_pfx(%Pfx{bits: 42, maxlen: 0})
    refute is_pfx(%Pfx{bits: '11', maxlen: 0})

    # use is_pfx as clause
    f = fn
      x when is_pfx(x) -> true
      _ -> false
    end

    # test f.(pfx) actually works
    assert f.(%Pfx{bits: <<>>, maxlen: 0})

    # a map does not a struct make
    refute f.(%{bits: <<>>, maxlen: 0})

    # other cases that are not a %Pfx{}
    refute f.('123')
    refute f.([])
    refute f.({1, 2, 3, 4})
    refute f.({{1, 2, 3, 4}, 32})

    # more generic cases
    Enum.all?(@bad_representations, fn x -> refute(f.(x)) end)

    # lets end on a positive note
    Enum.all?(@ip4_representations, fn x -> assert(f.(new(x))) end)
    Enum.all?(@ip6_representations, fn x -> assert(f.(new(x))) end)
  end

  # New/1, New/2

  test "new/1, new/2" do
    # good args
    f = fn x -> assert new(x) end
    Enum.all?(@ip4_representations, f)
    Enum.all?(@ip6_representations, f)

    # bad args
    f = fn x -> assert_raise ArgumentError, fn -> new(x) end end
    Enum.all?(@bad_representations, f)

    # identity
    null = %Pfx{bits: <<>>, maxlen: 0}
    assert null == new(null)
    assert null == new(<<>>, 0)
    # binary is also a bitstring
    assert null == new("", 0)

    # ipv4
    addr = %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}
    assert addr == new(addr)
    assert addr == new("1.2.3.4")
    assert addr == new("1.2.3.4/32")
    assert addr == new({1, 2, 3, 4})
    assert addr == new({{1, 2, 3, 4}, 32})
    assert addr == new({{1, 2, 3, 4}, nil})

    netw = %Pfx{bits: <<1, 2, 3>>, maxlen: 32}
    assert netw == new(netw)
    assert netw == new("1.2.3.0/24")
    # mask is 'applied'
    assert netw == new("1.2.3.4/24")
    assert netw == new({{1, 2, 3, 0}, 24})
    assert netw == new({{1, 2, 3, 4}, 24})

    # ipv6
    addr = %Pfx{bits: <<0xACDC::16, 0x1976::16, 0::96>>, maxlen: 128}
    assert addr == new(addr)
    assert addr == new(<<0xAC, 0xDC, 0x19, 0x76, 0::96>>, 128)
    assert addr == new("acdc:1976::")
    assert addr == new({0xACDC, 0x1976, 0, 0, 0, 0, 0, 0})
    assert addr == new({{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 128})
    # nil means no mask supplied, default to full mask
    assert addr == new({{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, nil})

    netw = %Pfx{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128}
    assert netw == new(netw)
    assert netw == new(<<0xACDC::16, 0x1976::16>>, 128)
    assert netw == new("acdc:1976::/32")
    assert netw == new({{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 32})
  end

  # Cut/3

  test "cut/3" do
    # good args
    Enum.all?(@ip4_representations, fn x -> assert cut(x, 0, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert cut(x, 0, 0) end)

    # bad args
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> cut(x, 0, 0) end end)

    bits = %Pfx{bits: <<255, 0>>, maxlen: 16}

    # cut zero bits
    assert %Pfx{bits: <<>>, maxlen: 0} == cut(bits, 0, 0)
    assert %Pfx{bits: <<>>, maxlen: 0} == cut(bits, 15, 0)

    # cut one bit
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == cut(bits, 0, 1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, 8, 1)

    # cut more bits
    assert %Pfx{bits: <<255>>, maxlen: 8} = cut(bits, 0, 8)
    assert %Pfx{bits: <<0>>, maxlen: 8} = cut(bits, 8, 8)
    assert %Pfx{bits: <<240>>, maxlen: 8} = cut(bits, 4, 8)

    # cuts to the left as well
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == cut(bits, 0, -1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, 8, -1)
    assert %Pfx{bits: <<255>>, maxlen: 8} = cut(bits, 7, -8)
    assert %Pfx{bits: <<0>>, maxlen: 8} = cut(bits, 15, -8)
    assert %Pfx{bits: <<240>>, maxlen: 8} = cut(bits, 11, -8)

    # cuts relative to the end of pfx.bits
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, -1, -1)
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == cut(bits, -9, -1)
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == cut(bits, -16, -1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, -1, -1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, -8, -1)
    assert %Pfx{bits: <<255>>, maxlen: 8} == cut(bits, -9, -8)
    assert %Pfx{bits: <<0>>, maxlen: 8} == cut(bits, -1, -8)
    assert %Pfx{bits: <<240>>, maxlen: 8} = cut(bits, -5, -8)
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == cut(bits, -9, 1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, -8, 1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, -1, 1)
    assert %Pfx{bits: <<128>>, maxlen: 8} == cut(bits, -9, 8)
    assert %Pfx{bits: <<240>>, maxlen: 8} = cut(bits, -12, 8)
  end

  # Bit/2

  test "bit/2" do
    # good args
    Enum.all?(@ip4_representations, fn x -> assert bit(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert bit(x, 0) end)

    # bad args
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bit(x, 0) end end)

    # out of range
    assert_raise ArgumentError, fn -> bit(%Pfx{bits: <<255>>, maxlen: 16}, 16) end
    assert_raise ArgumentError, fn -> bit(%Pfx{bits: <<255>>, maxlen: 16}, -17) end

    # first bit
    assert 1 == bit(%Pfx{bits: <<255, 0>>, maxlen: 16}, 0)

    # last bit
    assert 0 == bit(%Pfx{bits: <<255, 0>>, maxlen: 16}, 15)

    # inbetween bits
    assert 0 == bit(%Pfx{bits: <<255, 255, 0, 0>>, maxlen: 32}, 16)
    assert 0 == bit("255.255.0.0", 16)
    assert 0 == bit("255.255.0.0/32", 16)
    assert 0 == bit({255, 255, 0, 0}, 16)
    assert 0 == bit({{255, 255, 0, 0}, 32}, 16)
    assert 1 == bit(%Pfx{bits: <<255, 255, 0, 0>>, maxlen: 32}, 15)
    assert 1 == bit("255.255.0.0", 15)
    assert 1 == bit("255.255.0.0/32", 15)
    assert 1 == bit({255, 255, 0, 0}, 15)
    assert 1 == bit({{255, 255, 0, 0}, 32}, 15)
  end

  # Bits/3

  test "bits/3" do
    f = fn x -> assert_raise ArgumentError, fn -> bits(x, 0, 0) end end
    Enum.all?(@bad_representations, f)
  end

  # Bitwise Ops

  # Cast/1
  test "cast/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> cast(x) end end)
  end

  # Bnot/1
  test "bnot/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bnot(x) end end)
  end

  # Band/2
  test "band/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> band(x, x) end end)
  end

  # Bor/2
  test "bor/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bor(x, x) end end)
  end

  # Bxor/2
  test "bxor/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bxor(x, x) end end)
  end

  # Brot/2
  test "brot/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> brot(x, 0) end end)
  end

  # Bsl/2
  test "bsl/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bsl(x, 0) end end)
  end

  # Bsr/2
  test "bsr/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bsr(x, 0) end end)
  end

  # Padr/1
  test "padr/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padr(x) end end)
  end

  # Padr/2
  test "padr/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padr(x, 0) end end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padr(x, 1) end end)
  end

  # Padl/1
  test "padl/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padl(x) end end)
  end

  # Padl/2
  test "padl/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padl(x, 0) end end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padl(x, 1) end end)
  end

  # Bset/2
  test "bset/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bset(x, 0) end end)

    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bset(x, 1) end end)
  end

  # Partition
  test "partition/2" do
  end

  # Fields/2
  test "fields/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> fields(x, 1) end end)
  end

  # Digits/2
  test "digits/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> digits(x, 1) end end)
  end

  # Sibling/2
  test "sibling/2" do
    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> sibling(x, 0) end
    end)
  end

  # Size/1
  test "size/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> size(x) end end)
  end

  # Member/2
  test "member/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> member(x, 0) end end)
  end

  # Member?/2
  test "member?/2" do
  end

  # format/2
  test "format/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> format(x) end end)
  end

  # Compare/2
  test "compare/2" do
    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> compare(x, x) end
    end)
  end

  # Contrast/2
  test "contrast/2" do
    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> contrast(x, x) end
    end)
  end

  # Network/1
  test "network/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> network(x) end end)
  end

  # Broadcast/1
  test "broadcast/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> broadcast(x) end end)
  end

  # Hosts/1
  test "hosts/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> hosts(x) end end)
  end

  # Host/2
  test "host/2" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> host(x, 0) end end)
  end

  # Mask/1
  test "mask/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> mask(x) end end)
  end

  # Inv_mask/1
  test "inv_mask/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> inv_mask(x) end end)
  end

  # Neighbor/1
  test "neighbor/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> neighbor(x) end end)
  end

  # Teredo/1
  test "teredo/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> teredo(x) end end)
  end

  # Teredo?/1
  test "teredo?/1" do
  end

  # Multicast?/1
  test "multicast?/1" do
  end

  # Multicast/1
  test "multicast/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> multicast(x) end end)
  end

  # Link_local?/1
  test "link_local?/1" do
  end

  # Link_local/1
  test "link_local/1" do
    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> link_local(x) end
    end)
  end

  # Nat64_encode/2
  test "nat64_encode/2" do
    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> nat64_encode(x, x) end
    end)
  end

  # Nat64_decode/1
  test "nat64_decode/1" do
    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> nat64_decode(x) end
    end)
  end

  # Dns_ptr/1
  test "dns_ptr/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> dns_ptr(x) end end)
  end

  test "functions accept valid ip4 input" do
    list = @ip4_representations
    Enum.all?(list, fn x -> assert cast(x) end)
    Enum.all?(list, fn x -> assert bnot(x) end)
    Enum.all?(list, fn x -> assert band(x, x) end)
    Enum.all?(list, fn x -> assert bor(x, x) end)
    Enum.all?(list, fn x -> assert bxor(x, x) end)
    Enum.all?(list, fn x -> assert brot(x, 0) end)
    Enum.all?(list, fn x -> assert bsl(x, 0) end)
    Enum.all?(list, fn x -> assert bsr(x, 0) end)
    Enum.all?(list, fn x -> assert padr(x) end)
    Enum.all?(list, fn x -> assert padr(x, 0) end)
    Enum.all?(list, fn x -> assert padr(x, 1) end)
    Enum.all?(list, fn x -> assert padl(x) end)
    Enum.all?(list, fn x -> assert padl(x, 0) end)
    Enum.all?(list, fn x -> assert padl(x, 1) end)
    Enum.all?(list, fn x -> assert bset(x, 0) end)
    Enum.all?(list, fn x -> assert bset(x, 1) end)
    # partition done separately
    Enum.all?(list, fn x -> assert fields(x, 1) end)
    Enum.all?(list, fn x -> assert digits(x, 1) end)
    Enum.all?(list, fn x -> assert sibling(x, 0) end)
    Enum.all?(list, fn x -> assert size(x) end)
    Enum.all?(list, fn x -> assert member(x, 0) end)
    # func? never raise errors, so
    Enum.all?(list, fn x -> assert format(x) end)
    Enum.all?(list, fn x -> assert compare(x, x) end)
    Enum.all?(list, fn x -> assert contrast(x, x) end)
    # IP'ish
    Enum.all?(list, fn x -> assert network(x) end)
    Enum.all?(list, fn x -> assert broadcast(x) end)
    # hosts will try to enumerate, which for 0/0 is quite alot
    # Enum.all?(list, fn x -> assert hosts(x) end)
    Enum.all?(list, fn x -> assert host(x, 0) end)
    Enum.all?(list, fn x -> assert mask(x) end)
    Enum.all?(list, fn x -> assert inv_mask(x) end)
    Enum.all?(list, fn x -> assert neighbor(x) end)
    # IP specific
    Enum.all?(list, fn x -> assert nil == teredo(x) end)
    Enum.all?(list, fn x -> assert nil == multicast(x) end)
    # link_local returns nil for some, a map for others
    # Enum.all?(list, fn x -> assert nil == link_local(x) end)
    # the next two raise arg error cause 1st arg is not ipv6 address
    Enum.all?(list, fn x -> assert_raise ArgumentError, fn -> nat64_encode(x, x) end end)
    Enum.all?(list, fn x -> assert_raise ArgumentError, fn -> nat64_decode(x) end end)
    Enum.all?(list, fn x -> assert dns_ptr(x) end)
  end

  test "functions accept valid ip6 input" do
    list = @ip6_representations
    Enum.all?(list, fn x -> assert new(x) end)
    Enum.all?(list, fn x -> assert cut(x, 0, 0) end)
    Enum.all?(list, fn x -> assert bit(x, 0) end)
    Enum.all?(list, fn x -> assert cast(x) end)
    Enum.all?(list, fn x -> assert bnot(x) end)
    Enum.all?(list, fn x -> assert band(x, x) end)
    Enum.all?(list, fn x -> assert bor(x, x) end)
    Enum.all?(list, fn x -> assert bxor(x, x) end)
    Enum.all?(list, fn x -> assert brot(x, 0) end)
    Enum.all?(list, fn x -> assert bsl(x, 0) end)
    Enum.all?(list, fn x -> assert bsr(x, 0) end)
    Enum.all?(list, fn x -> assert padr(x) end)
    Enum.all?(list, fn x -> assert padr(x, 0) end)
    Enum.all?(list, fn x -> assert padr(x, 1) end)
    Enum.all?(list, fn x -> assert padl(x) end)
    Enum.all?(list, fn x -> assert padl(x, 0) end)
    Enum.all?(list, fn x -> assert padl(x, 1) end)
    Enum.all?(list, fn x -> assert bset(x, 0) end)
    Enum.all?(list, fn x -> assert bset(x, 1) end)
    # partition done separately
    Enum.all?(list, fn x -> assert fields(x, 1) end)
    Enum.all?(list, fn x -> assert digits(x, 1) end)
    Enum.all?(list, fn x -> assert sibling(x, 0) end)
    Enum.all?(list, fn x -> assert size(x) end)
    Enum.all?(list, fn x -> assert member(x, 0) end)
    # func? never raise errors, so
    Enum.all?(list, fn x -> assert format(x) end)
    Enum.all?(list, fn x -> assert compare(x, x) end)
    Enum.all?(list, fn x -> assert contrast(x, x) end)
    # IP'ish
    Enum.all?(list, fn x -> assert network(x) end)
    Enum.all?(list, fn x -> assert broadcast(x) end)
    # hosts will try to enumerate, which for 0/0 is quite alot
    # Enum.all?(list, fn x -> assert hosts(x) end)
    Enum.all?(list, fn x -> assert host(x, 0) end)
    Enum.all?(list, fn x -> assert mask(x) end)
    Enum.all?(list, fn x -> assert inv_mask(x) end)
    Enum.all?(list, fn x -> assert neighbor(x) end)
    # IP specific
    Enum.all?(list, fn x -> assert nil == teredo(x) end)
    Enum.all?(list, fn x -> assert nil == multicast(x) end)
    # link_local returns nil for some, a map for others
    Enum.all?(list, fn x -> assert nil == link_local(x) end)
    # Enum.all?(list, fn x -> assert nat64_encode(x, x) end)
    # there are non-nat64 addresses in the list
    # Enum.all?(list, fn x -> assert nat64_decode(x) end)
    Enum.all?(list, fn x -> assert dns_ptr(x) end)
  end
end
