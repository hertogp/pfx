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

  @eui_representations [
    %Pfx{bits: <<>>, maxlen: 48},
    {0, 0, 0, 0, 0, 0},
    {{0, 0, 0, 0, 0, 0}, 0},
    "aa:bb:cc:dd:ee:ff",
    "aa-bb-cc-dd-ee-ff",
    "aabb.ccdd.eeff",
    "aa:bb:cc:dd:ee:ff/48",
    "aa-bb-cc-dd-ee-ff/48",
    "aabb.ccdd.eeff/48",
    "aa:bb:cc:dd:ee:ff/8",
    "aa-bb-cc-dd-ee-ff/8",
    "aabb.ccdd.eeff/8",
    %Pfx{bits: <<>>, maxlen: 64},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {{0, 0, 0, 0, 0, 0, 0, 0}, 0},
    "aa:bb:cc:dd:ee:ff:11:22",
    "aa-bb-cc-dd-ee-ff-11-22",
    "aa:bb:cc:dd:ee:ff:11:22/48",
    "aa-bb-cc-dd-ee-ff-11-22/48",
    "aa:bb:cc:dd:ee:ff:11:22/8",
    "aa-bb-cc-dd-ee-ff-11-22/8"
  ]
  @bad_euis [
    %Pfx{bits: <<>>, maxlen: 40},
    {0, 0, 0, 0},
    {{0, 0, 0, 0}, 0},
    {0, 0, 0, 0, 0, 0, 0},
    {{0, 0, 0, 0, 0, 0, 0}, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0},
    {{0, 0, 0, 0, 0, 0, 0, 0, 0}, 0},
    "aa+bb:cc:dd:ee:ff",
    "aa.bb:cc:dd:ee:ff",
    "aabbccddeeff"
  ]

  test "address/1" do
    Enum.all?(@ip4_representations, fn x -> assert address(x) end)
    Enum.all?(@ip6_representations, fn x -> assert address(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> address(x) end end)

    # results mirror the argument
    assert "1.2.3.4" == address("1.2.3.4/0")
    assert "1.2.3.4" == address("1.2.3.4/9")
    assert "1.2.3.4" == address("1.2.3.4/32")
    assert {{1, 2, 3, 4}, 32} == address({{1, 2, 3, 4}, 16})
    assert {{1, 2, 3, 4, 5, 6, 7, 8}, 128} == address({{1, 2, 3, 4, 5, 6, 7, 8}, 64})

    # these have no effect
    assert {1, 2, 3, 4} == address({1, 2, 3, 4})
    assert {1, 2, 3, 4, 5, 6, 7, 8} == address({1, 2, 3, 4, 5, 6, 7, 8})
    assert %Pfx{bits: <<1, 2, 3>>, maxlen: 32} == address(%Pfx{bits: <<1, 2, 3>>, maxlen: 32})
    assert %Pfx{bits: <<>>, maxlen: 128} == address(%Pfx{bits: <<>>, maxlen: 128})
  end

  test "band/2" do
    Enum.all?(@ip4_representations, fn x -> assert band(x, x) end)
    Enum.all?(@ip6_representations, fn x -> assert band(x, x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> band(x, x) end end)

    # needs args to be of same type
    assert_raise ArgumentError, fn -> band("1.1.1.1", "acdc::") end

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 8} ==
             band(%Pfx{bits: <<>>, maxlen: 8}, %Pfx{bits: <<>>, maxlen: 8})

    assert %Pfx{bits: <<>>, maxlen: 8} ==
             band(%Pfx{bits: <<>>, maxlen: 8}, %Pfx{bits: <<255>>, maxlen: 8})

    assert %Pfx{bits: <<0>>, maxlen: 8} ==
             band(%Pfx{bits: <<255>>, maxlen: 8}, %Pfx{bits: <<>>, maxlen: 8})

    # results mirror form of 1st argument
    assert "1.2.3.4" == band("1.2.3.4", "255.255.255.255")
    assert "1.2.3.0" == band("1.2.3.4", "255.255.255.0")
    assert {1, 2, 0, 4} == band({1, 2, 3, 4}, "255.255.0.255")

    # band does not change bit_size of its first argument
    assert {{1, 0, 0, 0}, 16} == band({{1, 2, 3, 4}, 16}, "255.0.0.0")
  end

  test "bit/2" do
    Enum.all?(@ip4_representations, fn x -> assert bit(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert bit(x, 0) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bit(x, 0) end end)

    # out of range
    assert_raise ArgumentError, fn -> bit(%Pfx{bits: <<255>>, maxlen: 16}, 16) end
    assert_raise ArgumentError, fn -> bit(%Pfx{bits: <<255>>, maxlen: 16}, -17) end

    # first bit
    assert 1 == bit(%Pfx{bits: <<255, 0>>, maxlen: 16}, 0)
    assert 1 == bit(%Pfx{bits: <<255, 0>>, maxlen: 16}, -16)

    # last bit
    assert 0 == bit(%Pfx{bits: <<255, 0>>, maxlen: 16}, 15)
    assert 0 == bit(%Pfx{bits: <<255, 0>>, maxlen: 16}, -1)

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

  test "bits/3" do
    Enum.all?(@ip4_representations, fn x -> assert bits(x, 0, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert bits(x, 0, 0) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> bits(x, 0, 0) end
    end)

    pfx = %Pfx{bits: <<0, 0, 128, 1>>, maxlen: 32}

    # out of range
    assert_raise ArgumentError, fn -> bits(pfx, 0, 33) end
    assert_raise ArgumentError, fn -> bits(pfx, 31, 2) end
    assert_raise ArgumentError, fn -> bits(pfx, 32, 0) end

    # no bits
    assert <<>> == bits(pfx, 0, 0)
    assert <<>> == bits(pfx, 31, 0)

    # first bits
    assert <<0::1>> == bits(pfx, 0, 1)
    assert <<0::2>> == bits(pfx, 0, 2)

    # last bits
    assert <<1::1>> == bits(pfx, 31, 1)
    assert <<1::2>> == bits(pfx, 30, 2)

    # other bits
    assert <<0>> == bits(pfx, 0, 8)
    assert <<0>> == bits(pfx, 8, 8)
    assert <<128>> == bits(pfx, 16, 8)
    assert <<1>> == bits(pfx, 24, 8)

    # non byte boundary
    assert <<1>> == bits(pfx, 9, 8)
    assert <<1::5>> == bits(pfx, 12, 5)
    assert <<2>> == bits(pfx, 10, 8)

    # cidr
    assert <<0::1>> == bits("0.0.128.1", 0, 1)
    assert <<1::1>> == bits("acdc::", 0, 1)
    assert <<0xAC>> == bits("acdc::", 0, 8)
  end

  test "bnot/1" do
    Enum.all?(@ip4_representations, fn x -> assert bnot(x) end)
    Enum.all?(@ip6_representations, fn x -> assert bnot(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bnot(x) end end)

    # no bits, no inverted bits
    assert %Pfx{bits: <<>>, maxlen: 10} == bnot(%Pfx{bits: <<>>, maxlen: 10})

    # bnot inverts the bits
    assert %Pfx{bits: <<0>>, maxlen: 8} == bnot(%Pfx{bits: <<255>>, maxlen: 8})
    assert %Pfx{bits: <<127>>, maxlen: 8} == bnot(%Pfx{bits: <<128>>, maxlen: 8})

    # bnot twice yields original
    assert %Pfx{bits: <<123>>, maxlen: 16} == bnot(bnot(%Pfx{bits: <<123>>, maxlen: 16}))

    # results mirror argument
    assert "0.0.255.255" == bnot("255.255.0.0")
    assert {0, 0, 0, 252} == bnot({255, 255, 255, 3})
    assert {{0, 255, 0, 255}, 32} == bnot({{255, 0, 255, 0}, 32})

    # mask is omitted if full length
    assert "255.255.255.255" == bnot("0.0.0.0/32")

    # mask is applied first
    assert "255.255.255.0/24" == bnot("0.0.0.0/24")
  end

  test "bor/2" do
    Enum.all?(@ip4_representations, fn x -> assert bor(x, x) end)
    Enum.all?(@ip6_representations, fn x -> assert bor(x, x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bor(x, x) end end)

    # needs args to be of same type
    assert_raise ArgumentError, fn -> bor("1.1.1.1", "acdc::") end

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 8} ==
             bor(%Pfx{bits: <<>>, maxlen: 8}, %Pfx{bits: <<>>, maxlen: 8})

    assert %Pfx{bits: <<>>, maxlen: 8} ==
             bor(%Pfx{bits: <<>>, maxlen: 8}, %Pfx{bits: <<255>>, maxlen: 8})

    assert %Pfx{bits: <<255>>, maxlen: 8} ==
             bor(%Pfx{bits: <<255>>, maxlen: 8}, %Pfx{bits: <<>>, maxlen: 8})

    # results mirror form of 1st argument
    assert "255.255.255.255" == bor("1.2.3.4", "255.255.255.255")
    assert "255.255.255.4" == bor("1.2.3.4", "255.255.255.0")
    assert {255, 255, 3, 255} == bor({1, 2, 3, 4}, "255.255.0.255")

    # bor does not change bit_size of its first argument
    assert {{255, 2, 0, 0}, 16} == bor({{1, 2, 3, 4}, 16}, "255.0.0.0")
  end

  test "broadcast/1" do
    Enum.all?(@ip4_representations, fn x -> assert broadcast(x) end)
    Enum.all?(@ip6_representations, fn x -> assert broadcast(x) end)

    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> broadcast(x) end end)

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == broadcast(%Pfx{bits: <<>>, maxlen: 0})

    # only one bit
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == broadcast(%Pfx{bits: <<>>, maxlen: 1})

    # more bits
    assert %Pfx{bits: <<255, 255>>, maxlen: 16} == broadcast(%Pfx{bits: <<255>>, maxlen: 16})

    # full address
    assert %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32} ==
             broadcast(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32})

    # all formats
    assert "1.1.1.255" == broadcast("1.1.1.0/24")
    assert "1.255.255.255" == broadcast("1.0.0.0/8")
    assert "acdc:1976:ffff:ffff:ffff:ffff:ffff:ffff" == broadcast("acdc:1976::/32")
    assert {{1, 2, 3, 255}, 32} == broadcast({{1, 2, 3, 4}, 24})
  end

  test "brot/2" do
    Enum.all?(@ip4_representations, fn x -> assert brot(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert brot(x, 0) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> brot(x, 0) end end)

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == brot(%Pfx{bits: <<>>, maxlen: 0}, 0)
    assert %Pfx{bits: <<>>, maxlen: 0} == brot(%Pfx{bits: <<>>, maxlen: 0}, -1)
    assert %Pfx{bits: <<>>, maxlen: 0} == brot(%Pfx{bits: <<>>, maxlen: 0}, 1)

    assert %Pfx{bits: <<>>, maxlen: 120} == brot(%Pfx{bits: <<>>, maxlen: 120}, 0)
    assert %Pfx{bits: <<>>, maxlen: 120} == brot(%Pfx{bits: <<>>, maxlen: 120}, -1)
    assert %Pfx{bits: <<>>, maxlen: 120} == brot(%Pfx{bits: <<>>, maxlen: 120}, 1)

    # some bits
    assert %Pfx{bits: <<127>>, maxlen: 8} == brot(%Pfx{bits: <<127>>, maxlen: 8}, 0)
    assert %Pfx{bits: <<127>>, maxlen: 8} == brot(%Pfx{bits: <<127>>, maxlen: 8}, 8)
    assert %Pfx{bits: <<254>>, maxlen: 8} == brot(%Pfx{bits: <<127>>, maxlen: 8}, -1)
    assert %Pfx{bits: <<191>>, maxlen: 8} == brot(%Pfx{bits: <<127>>, maxlen: 8}, 1)

    # same representation for results
    assert "2.3.4.1" == brot("1.2.3.4", -8)
    assert {2, 3, 4, 1} == brot({1, 2, 3, 4}, -8)
    # note {{1,2,3,4},24} => {1, 2, 3} => rotate left by 8 bits gives {2, 3, 1}
    assert {{2, 3, 1, 0}, 24} == brot({{1, 2, 3, 4}, 24}, -8)
    assert {{2, 3, 1, 0}, 24} == brot({{1, 2, 3, 4}, 24}, -8)
  end

  test "bset/2" do
    Enum.all?(@ip4_representations, fn x -> assert bset(x, 0) end)
    Enum.all?(@ip4_representations, fn x -> assert bset(x, 1) end)
    Enum.all?(@ip6_representations, fn x -> assert bset(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert bset(x, 1) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bset(x, 0) end end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bset(x, 1) end end)

    # bad input
    assert_raise ArgumentError, fn -> bset(%Pfx{bits: <<255>>, maxlen: 8}, -1) end
    assert_raise ArgumentError, fn -> bset(%Pfx{bits: <<255>>, maxlen: 8}, 2) end

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == bset(%Pfx{bits: <<>>, maxlen: 0}, 0)
    assert %Pfx{bits: <<>>, maxlen: 0} == bset(%Pfx{bits: <<>>, maxlen: 0}, 1)

    # some bits
    assert %Pfx{bits: <<255>>, maxlen: 24} == bset(%Pfx{bits: <<0>>, maxlen: 24}, 1)
    assert %Pfx{bits: <<0>>, maxlen: 24} == bset(%Pfx{bits: <<255>>, maxlen: 24}, 0)

    # same representation for the result
    assert "0.0.0.0" == bset("0.0.0.0", 0)
    assert "255.255.255.255" == bset("0.0.0.0", 1)
    assert "255.255.0.0/16" == bset("0.0.0.0/16", 1)
    assert "255.255.0.0/16" == bset("0.0.1.2/16", 1)
    assert {0, 0, 0, 0} == bset({0, 0, 0, 0}, 0)
    assert {255, 255, 255, 255} == bset({0, 1, 2, 3}, 1)
    assert {{255, 255, 255, 0}, 24} == bset({{0, 0, 0, 255}, 24}, 1)
  end

  test "bsl/2" do
    Enum.all?(@ip4_representations, fn x -> assert bsl(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert bsl(x, 0) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bsl(x, 0) end end)

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == bsl(%Pfx{bits: <<>>, maxlen: 0}, 0)
    assert %Pfx{bits: <<>>, maxlen: 0} == bsl(%Pfx{bits: <<>>, maxlen: 0}, -1)
    assert %Pfx{bits: <<>>, maxlen: 0} == bsl(%Pfx{bits: <<>>, maxlen: 0}, 1)

    # some bits
    assert %Pfx{bits: <<254>>, maxlen: 16} == bsl(%Pfx{bits: <<255>>, maxlen: 16}, 1)
    assert %Pfx{bits: <<127>>, maxlen: 16} == bsl(%Pfx{bits: <<255>>, maxlen: 16}, -1)
    assert %Pfx{bits: <<0>>, maxlen: 16} == bsl(%Pfx{bits: <<255>>, maxlen: 16}, 8)
    assert %Pfx{bits: <<0>>, maxlen: 16} == bsl(%Pfx{bits: <<255>>, maxlen: 16}, -8)
    # bit_size doesn't change
    assert %Pfx{bits: <<0>>, maxlen: 16} == bsl(%Pfx{bits: <<255>>, maxlen: 16}, 88)

    # same representation for results
    assert "2.3.4.0" == bsl("1.2.3.4", 8)
    assert "2.3.0.0/24" == bsl("1.2.3.4/24", 8)
    assert {2, 3, 4, 0} == bsl({1, 2, 3, 4}, 8)
    assert {0, 1, 2, 3} == bsl({1, 2, 3, 4}, -8)
  end

  test "bsr/2" do
    Enum.all?(@ip4_representations, fn x -> assert bsr(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert bsr(x, 0) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bsr(x, 0) end end)

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == bsr(%Pfx{bits: <<>>, maxlen: 0}, 0)
    assert %Pfx{bits: <<>>, maxlen: 0} == bsr(%Pfx{bits: <<>>, maxlen: 0}, -1)
    assert %Pfx{bits: <<>>, maxlen: 0} == bsr(%Pfx{bits: <<>>, maxlen: 0}, 1)

    # some bits
    assert %Pfx{bits: <<254>>, maxlen: 16} == bsr(%Pfx{bits: <<255>>, maxlen: 16}, -1)
    assert %Pfx{bits: <<127>>, maxlen: 16} == bsr(%Pfx{bits: <<255>>, maxlen: 16}, 1)
    assert %Pfx{bits: <<0>>, maxlen: 16} == bsr(%Pfx{bits: <<255>>, maxlen: 16}, -8)
    assert %Pfx{bits: <<0>>, maxlen: 16} == bsr(%Pfx{bits: <<255>>, maxlen: 16}, 8)
    # bit_size doesn't change
    assert %Pfx{bits: <<0>>, maxlen: 16} == bsr(%Pfx{bits: <<255>>, maxlen: 16}, 88)

    # same representation for results
    assert "2.3.4.0" == bsr("1.2.3.4", -8)
    assert "2.3.0.0/24" == bsr("1.2.3.4/24", -8)
    assert {2, 3, 4, 0} == bsr({1, 2, 3, 4}, -8)
    assert {0, 1, 2, 3} == bsr({1, 2, 3, 4}, 8)
  end

  test "bxor/2" do
    Enum.all?(@ip4_representations, fn x -> assert bxor(x, x) end)
    Enum.all?(@ip6_representations, fn x -> assert bxor(x, x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> bxor(x, x) end end)

    # needs args to be of same type
    assert_raise ArgumentError, fn -> bxor("1.1.1.1", "acdc::") end

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 8} ==
             bxor(%Pfx{bits: <<>>, maxlen: 8}, %Pfx{bits: <<>>, maxlen: 8})

    assert %Pfx{bits: <<>>, maxlen: 8} ==
             bxor(%Pfx{bits: <<>>, maxlen: 8}, %Pfx{bits: <<255>>, maxlen: 8})

    assert %Pfx{bits: <<255>>, maxlen: 8} ==
             bxor(%Pfx{bits: <<255>>, maxlen: 8}, %Pfx{bits: <<>>, maxlen: 8})

    # results mirror form of 1st argument
    assert "254.253.252.251" == bxor("1.2.3.4", "255.255.255.255")
    assert "254.253.252.4" == bxor("1.2.3.4", "255.255.255.0")
    assert {254, 253, 3, 251} == bxor({1, 2, 3, 4}, "255.255.0.255")

    # bor does not change bit_size of its first argument
    assert {{254, 2, 0, 0}, 16} == bxor({{1, 2, 3, 4}, 16}, "255.0.0.0")
  end

  test "cast/1" do
    Enum.all?(@ip4_representations, fn x -> assert cast(x) end)
    Enum.all?(@ip6_representations, fn x -> assert cast(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> cast(x) end end)

    # empty bits
    assert 0 == cast(%Pfx{bits: <<>>, maxlen: 32})
    assert 0 == cast(%Pfx{bits: <<>>, maxlen: 0})

    # cast pads right, then turns it into a number
    assert 255 == cast(%Pfx{bits: <<255>>, maxlen: 8})
    assert 128 == cast(%Pfx{bits: <<1::1>>, maxlen: 8})
    assert 65535 - 255 == cast(%Pfx{bits: <<255>>, maxlen: 16})
  end

  test "compare/2" do
    Enum.all?(@ip4_representations, fn x -> assert compare(x, x) end)
    Enum.all?(@ip6_representations, fn x -> assert compare(x, x) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> compare(x, x) end
    end)

    # needs args to be of same type
    assert_raise ArgumentError, fn -> compare("1.1.1.1", "acdc::") end

    # full prefixes
    assert :lt == compare("1.1.1.1", "1.1.1.2")
    assert :gt == compare("1.1.1.1", "1.1.1.0")
    assert :eq == compare("1.1.1.1", "1.1.1.1")

    # networks
    assert :lt == compare("10.11.12.0/24", "10.11.0.0/16")
    assert :gt == compare("10.11.0.0/16", "10.11.12.0/24")
    assert :eq == compare("10.11.0.0/16", "10.11.0.0/16")
  end

  test "contrast/2" do
    Enum.all?(@ip4_representations, fn x -> assert contrast(x, x) end)
    Enum.all?(@ip6_representations, fn x -> assert contrast(x, x) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> contrast(x, x) end
    end)

    # needs args to be of same type
    assert_raise ArgumentError, fn -> contrast("1.1.1.1", "acdc::") end

    assert :equal == contrast(new(<<10, 10>>, 32), new(<<10, 10>>, 32))
    assert :more == contrast(new(<<10, 10, 10>>, 32), new(<<10, 10>>, 32))
    assert :less == contrast(new(<<10, 10>>, 32), new(<<10, 10, 10>>, 32))
    assert :left == contrast(new(<<10, 10>>, 32), new(<<10, 11>>, 32))
    assert :right == contrast(new(<<10, 11>>, 32), new(<<10, 10>>, 32))
    assert :disjoint == contrast(new(<<10, 10>>, 32), new(<<10, 12>>, 32))
    assert :disjoint == contrast("10.10.0.0/16", %Pfx{bits: <<10, 12>>, maxlen: 32})
    assert :more == contrast(%Pfx{bits: <<10, 10, 10>>, maxlen: 32}, {{10, 10, 0, 0}, 16})
    assert :more == contrast("10.10.10.0/24", "10.10.0.0/16")
  end

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

  test "digits/2" do
    Enum.all?(@ip4_representations, fn x -> assert digits(x, 1) end)
    Enum.all?(@ip6_representations, fn x -> assert digits(x, 1) end)

    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> digits(x, 1) end end)

    # no bits, means no actual digits and a 0 for length/mask
    assert {{}, 0} == digits(%Pfx{bits: <<>>, maxlen: 0}, 1)

    # just the bits
    assert {{1, 1, 1, 1, 0, 0, 0, 0}, 8} == digits(%Pfx{bits: <<0b11110000>>, maxlen: 8}, 1)
    assert {{1, 2, 3, 0}, 24} = digits("1.2.3.0/24", 8)
    assert {{1, 2, 3, 0}, 32} = digits("1.2.3.0", 8)

    assert {{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 32} == digits("acdc:1976::/32", 16)
    assert {{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 128} == digits("acdc:1976::", 16)

    # nibbles
    assert {{0xA, 0xC, 0xD, 0xC, 0x1, 0x9, 0x7, 0x6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0}, 128} == digits("acdc:1976::", 4)
  end

  test "dns_ptr/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> dns_ptr(x) end end)

    # dns_ptr only works for IPv4 or IPv6
    assert_raise ArgumentError, fn -> dns_ptr(%Pfx{bits: <<>>, maxlen: 0}) end
    assert_raise ArgumentError, fn -> dns_ptr(%Pfx{bits: <<255>>, maxlen: 16}) end
    assert_raise ArgumentError, fn -> dns_ptr(%Pfx{bits: <<255, 0>>, maxlen: 24}) end
    assert_raise ArgumentError, fn -> dns_ptr(%Pfx{bits: <<1, 2, 3, 4, 5, 6>>, maxlen: 48}) end

    # no bits
    assert_raise ArgumentError, fn -> dns_ptr(%Pfx{bits: <<>>, maxlen: 32}) end

    # bits are expanded to N*8 for IPv4 and N*4 for IPv6
    assert "0.in-addr.arpa" == dns_ptr(%Pfx{bits: <<0::1>>, maxlen: 32})
    assert "128.in-addr.arpa" == dns_ptr(%Pfx{bits: <<1::1>>, maxlen: 32})
    assert "0.ip6.arpa" == dns_ptr(%Pfx{bits: <<0::1>>, maxlen: 128})
    assert "8.ip6.arpa" == dns_ptr(%Pfx{bits: <<1::1>>, maxlen: 128})
    assert "16.1.in-addr.arpa" == dns_ptr(%Pfx{bits: <<1, 2::5>>, maxlen: 32})

    # digits are in reverse order
    assert "4.3.2.1.in-addr.arpa" = dns_ptr(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32})

    assert "6.7.9.1.c.d.c.a.ip6.arpa" =
             dns_ptr(%Pfx{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128})

    # accepts all formats
    assert "4.3.2.1.in-addr.arpa" == dns_ptr("1.2.3.4")
    assert "4.3.2.1.in-addr.arpa" == dns_ptr({1, 2, 3, 4})
    assert "4.3.2.1.in-addr.arpa" == dns_ptr({{1, 2, 3, 4}, 32})

    assert "3.2.1.in-addr.arpa" == dns_ptr("1.2.3.4/24")
    assert "3.2.1.in-addr.arpa" == dns_ptr({{1, 2, 3, 4}, 24})
  end

  test "drop/2" do
    Enum.all?(@ip4_representations, fn x -> assert drop(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert drop(x, 0) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> drop(x, 0) end end)

    # more bad input
    assert_raise ArgumentError, fn -> drop("1.1.1.1", -1) end
    assert_raise ArgumentError, fn -> drop("1.1.1.1", 1.0) end

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == drop(%Pfx{bits: <<>>, maxlen: 0}, 1)

    # one bit
    assert %Pfx{bits: <<>>, maxlen: 8} == drop(%Pfx{bits: <<1::1>>, maxlen: 8}, 1)

    # some bits
    assert %Pfx{bits: <<>>, maxlen: 8} == drop(%Pfx{bits: <<1>>, maxlen: 8}, 8)
    assert %Pfx{bits: <<1>>, maxlen: 16} == drop(%Pfx{bits: <<1, 2>>, maxlen: 16}, 8)

    # count > pfx.bits => just drops all bits
    assert %Pfx{bits: <<>>, maxlen: 128} == drop(%Pfx{bits: <<-1::128>>, maxlen: 128}, 512)

    # all representations
    assert "0.0.0.0/0" == drop("1.1.1.1", 32)
    assert "1.2.0.0/16" == drop("1.2.3.4", 16)
    assert {1, 2, 0, 0} == drop({1, 2, 3, 4}, 16)
    assert {{1, 2, 0, 0}, 16} == drop({{1, 2, 3, 4}, 32}, 16)
  end

  test "fields/2" do
    Enum.all?(@ip4_representations, fn x -> assert fields(x, 1) end)
    Enum.all?(@ip6_representations, fn x -> assert fields(x, 1) end)

    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> fields(x, 1) end end)

    # bad width
    assert_raise ArgumentError, fn -> fields(%Pfx{bits: <<255>>, maxlen: 8}, 0) end

    # no bits
    assert [] == fields(%Pfx{bits: <<>>, maxlen: 0}, 1)

    # some bits
    list = for _ <- 0..31, do: {0, 1}
    assert list == fields("0.0.0.0", 1)

    assert [{0, 4}, {1, 4}, {0, 4}, {1, 4}, {0, 4}, {1, 4}, {0, 4}, {1, 4}] ==
             fields("1.1.1.1", 4)

    assert [{1, 8}, {2, 8}, {3, 8}, {4, 8}] == fields("1.2.3.4", 8)

    # last bitfield may differ in width
    assert [{1, 8}, {2, 8}, {15, 4}] == fields("1.2.255.0/20", 8)
  end

  test "first/1" do
    Enum.all?(@ip4_representations, fn x -> assert first(x) end)
    Enum.all?(@ip6_representations, fn x -> assert first(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> first(x) end end)

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == first(%Pfx{bits: <<>>, maxlen: 0})

    # only one bit
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == first(%Pfx{bits: <<>>, maxlen: 1})

    # more bits
    assert %Pfx{bits: <<255, 0>>, maxlen: 16} == first(%Pfx{bits: <<255>>, maxlen: 16})

    # full address
    assert %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32} ==
             first(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32})

    # all formats
    assert "1.1.1.0" == first("1.1.1.255/24")
    assert "acdc:1976:0:0:0:0:0:0" == first("acdc:1976::/32")
    assert {{1, 2, 3, 0}, 32} == first({{1, 2, 3, 4}, 24})
  end

  test "flip/2" do
    # flip errors out on invalid bit positions
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> flip(x, 0) end end)

    # out of range
    assert_raise ArgumentError, fn -> flip("0.0.0.0/0", 0) end
    assert_raise ArgumentError, fn -> flip(%Pfx{bits: <<255>>, maxlen: 16}, 16) end
    assert_raise ArgumentError, fn -> flip(%Pfx{bits: <<255>>, maxlen: 16}, -17) end

    # first bit
    assert "127.0.0.0" == flip("255.0.0.0", 0)
    assert "127.0.0.0" == flip("255.0.0.0", -32)
    assert "128.0.0.0" == flip("0.0.0.0", 0)
    assert "128.0.0.0" == flip("0.0.0.0", -32)

    # last bit, 0->1 and 1->0
    assert "255.0.0.255" == flip("255.0.0.254", 31)
    assert "255.0.0.255" == flip("255.0.0.254", -1)
    assert "255.0.0.254" == flip("255.0.0.255", 31)
    assert "255.0.0.254" == flip("255.0.0.255", -1)

    # flip bits in prefixes, not just addresses
    assert "255.255.255.0/25" == flip("255.255.255.128/25", 24)
    assert "255.255.255.0/25" == flip("255.255.255.128/25", -1)

    # inbetween bits
    assert %Pfx{bits: <<255, 255, 128, 0>>, maxlen: 32} ==
             flip(%Pfx{bits: <<255, 255, 0, 0>>, maxlen: 32}, 16)

    assert "255.255.128.0" == flip("255.255.0.0", 16)
    assert {255, 255, 128, 0} == flip({255, 255, 0, 0}, 16)
    assert "255.255.0.0" == flip("255.255.128.0", 16)
    assert {255, 255, 0, 0} == flip({255, 255, 128, 0}, 16)

    assert "255.255.0.128" == flip("255.255.0.0/32", 24)
    assert {{255, 255, 0, 128}, 32} == flip({{255, 255, 0, 0}, 32}, 24)
  end

  test "format/2" do
    Enum.all?(@ip4_representations, fn x -> assert format(x) end)
    Enum.all?(@ip6_representations, fn x -> assert format(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> format(x) end end)

    # ipv4 defaults
    assert "1.2.3.4" == format(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32})

    # ipv6 nibbles, width & base
    opts = [width: 4, base: 16]

    assert "a.c.d.c.1.9.7.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0" ==
             format("acdc:1976::", opts)

    # reverse
    opts = Keyword.put(opts, :reverse, true)

    assert "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.7.9.1.c.d.c.a" ==
             format("acdc:1976::", opts)

    # unit
    assert "1111.1111" == format(%Pfx{bits: <<255>>, maxlen: 8}, width: 1, unit: 4)
    assert "11111111.00000000" == format(%Pfx{bits: <<255, 0>>, maxlen: 16}, width: 1, unit: 8)

    # ssep, note: MAC addresses are not lowercase
    assert "AA-BB-CC-DD-EE-FF" ==
             format(%Pfx{bits: <<0xAABBCCDDEEFF::48>>, maxlen: 48}, base: 16, ssep: "-")

    # lsep
    assert "1.2.3.0 / 24" == format(%Pfx{bits: <<1, 2, 3>>, maxlen: 32}, lsep: " / ")

    # padding
    assert "10/8" == format(%Pfx{bits: <<10>>, maxlen: 32}, padding: false)

    # mask
    assert "10" == format(%Pfx{bits: <<10>>, maxlen: 32}, padding: false, mask: false)

    # accept all formats
    assert "1.2.3.4" == format("1.2.3.4")
    assert "1.2.3.4" == format({1, 2, 3, 4})
    assert "1.2.3.4" == format({{1, 2, 3, 4}, 32})
    assert "1.2.3.0/24" == format({{1, 2, 3, 4}, 24})
    assert "1.2.3.0" == format({{1, 2, 3, 4}, 24}, mask: false)
  end

  test "from_hex/1" do
    addr = %Pfx{bits: <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF>>, maxlen: 48}
    assert addr == from_hex("aa:bb:cc:dd:ee:ff")
    assert addr == from_hex("aa-bb-cc-dd-ee-ff")
    assert addr == from_hex("aabb.ccdd.eeff")
    assert addr == from_hex("aa:bb.cc-dd.ee:ff")

    addr = %Pfx{bits: <<0x12, 0x34, 0x56>>, maxlen: 40}
    assert addr == from_hex("123456789A/24")
    assert addr == from_hex("123456789A/24", [])
    assert addr == from_hex("1|2|3|4|5|6|7|8|9|A/24", [?|])

    assert_raise ArgumentError, fn -> from_hex("ABCDEFG") end
    assert_raise ArgumentError, fn -> from_hex("12|34|AB") end
  end

  test "from_mac/1" do
    f = fn x -> assert from_mac(x) end
    Enum.all?(@eui_representations, f)

    # bad args
    f = fn x -> assert_raise ArgumentError, fn -> from_mac(x) end end
    Enum.all?(@bad_euis, f)

    # eui-48
    addr = %Pfx{bits: <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF>>, maxlen: 48}
    assert addr == from_mac(addr)
    assert addr == from_mac("aa:bb:cc:dd:ee:ff")
    assert addr == from_mac("aa-bb-cc-dd-ee-ff")
    assert addr == from_mac("aabb.ccdd.eeff")
    assert addr == from_mac("aa:bb.cc-dd.ee:ff")
    assert addr == from_mac({0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
    assert addr == from_mac({{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 48})
    # nil means no mask supplied, default to full mask
    assert addr == from_mac({{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, nil})

    oui = %Pfx{bits: <<0xAA, 0xBB, 0xCC>>, maxlen: 48}
    assert oui == from_mac(oui)
    assert oui == from_mac("aa:bb:cc:dd:ee:ff/24")
    assert oui == from_mac("aa-bb-cc-dd-ee-ff/24")
    assert oui == from_mac("aabb.ccdd.eeff/24")

    # eui-64
    addr = %Pfx{bits: <<0x11, 0x22, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF>>, maxlen: 64}
    assert addr == from_mac(addr)
    assert addr == from_mac("11:22:aa:bb:cc:dd:ee:ff")
    assert addr == from_mac("11-22-aa-bb-cc-dd-ee-ff")
    assert addr == from_mac({0x11, 0x22, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
    assert addr == from_mac({{0x11, 0x22, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 64})
    # nil means no mask supplied, default to full mask
    assert addr == from_mac({{0x11, 0x22, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, nil})

    oui = %Pfx{bits: <<0x11, 0x22, 0xAA>>, maxlen: 64}
    assert oui == from_mac(oui)
    assert oui == from_mac("11:22:aa:bb:cc:dd:ee:ff/24")
    assert oui == from_mac("11-22-aa-bb-cc-dd-ee-ff/24")
    assert oui == from_mac({{0x11, 0x22, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 24})
  end

  test "hosts/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> hosts(x) end end)

    # no bits; even zero bit prefix has itself as a member
    assert [%Pfx{bits: <<>>, maxlen: 0}] == hosts(%Pfx{bits: <<>>, maxlen: 0})

    # one bit
    assert [%Pfx{bits: <<0::1>>, maxlen: 1}, %Pfx{bits: <<1::1>>, maxlen: 1}] ==
             hosts(%Pfx{bits: <<>>, maxlen: 1})

    # more bits
    assert 16 == hosts("10.10.10.0/28") |> length()
    assert 256 == hosts("10.10.10.0/24") |> length()
    assert 65536 == hosts("10.10.0.0/16") |> length()

    # all representations
    assert 16 == hosts({{10, 10, 10, 0}, 28}) |> length()
    assert 256 == hosts({{10, 10, 10, 0}, 24}) |> length()
    assert 65536 == hosts({{10, 10, 10, 10}, 16}) |> length()

    # remember: hosts returns full length prefixes
    assert [{{1, 1, 1, 0}, 32}, {{1, 1, 1, 1}, 32}] == hosts({{1, 1, 1, 0}, 31})
  end

  test "host/2" do
    # essentially a wrapper for member/2
    Enum.all?(@ip4_representations, fn x -> assert host(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert host(x, 0) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> host(x, 0) end end)

    # all formats
    assert %Pfx{bits: <<10, 255>>, maxlen: 16} ==
             host(%Pfx{bits: <<>>, maxlen: 16}, 10 * 256 + 255)

    assert "1.1.1.63" == host("1.1.1.0/25", 63)
    assert {1, 1, 1, 91} == host({1, 1, 1, 91}, 0)
    assert {{1, 1, 1, 255}, 32} == host({{1, 1, 1, 0}, 24}, 255)
  end

  test "insert/3" do
    Enum.all?(@ip4_representations, fn x -> assert insert(x, <<>>, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert insert(x, <<>>, 0) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> insert(x, <<>>, 0) end
    end)

    # bad positions
    assert_raise ArgumentError, fn -> insert("1.1.1.1", <<>>, 32) end
    assert_raise ArgumentError, fn -> insert("1.1.1.1", <<>>, -33) end

    # bad bitstrings
    assert_raise ArgumentError, fn -> insert("1.1.1.1", 42, 0) end
    assert_raise ArgumentError, fn -> insert("1.1.1.1", [42], 0) end

    # prepend
    assert "255.1.2.3" == insert("1.2.3.0/24", <<255>>, 0)
    assert "0.0.1.2" == insert("1.2.3.0/24", <<0, 0>>, 0)

    # append
    assert "255.255.0.0/16" == insert("255.0.0.0/8", <<255>>, 8)
    assert "255.255.255.0/24" == insert("255.255.0.0/16", <<255>>, 16)
    assert "255.255.255.255" == insert("255.255.0.0/16", <<255, 255>>, 16)

    # silently clip to pfx.maxlen
    assert "1.2.3.4" == insert("0.0.0.0", <<1, 2, 3, 4, 5, 6, 7, 8, 9>>, 0)
    assert "1.2.3.4" == insert("1.2.0.0/16", <<3, 4, 5, 6, 7, 8, 9>>, 16)

    # representations
    assert {1, 2, 3, 4} == insert({1, 2, 3, 0}, <<4>>, 24)
    assert {{1, 2, 3, 0}, 24} == insert({{1, 2, 0, 0}, 16}, <<3>>, 16)
    assert "1.2.3.0/25" == insert("1.2.3.0/24", <<0::1>>, 24)
    assert "1.2.3.128/25" == insert("1.2.3.0/24", <<1::1>>, 24)

    assert %Pfx{bits: <<1, 2, 3, 1::1>>, maxlen: 32} ==
             insert(%Pfx{bits: <<1, 2, 3>>, maxlen: 32}, <<1::1>>, 24)
  end

  test "inv_mask/1" do
    Enum.all?(@ip4_representations, fn x -> assert inv_mask(x) end)
    Enum.all?(@ip6_representations, fn x -> assert inv_mask(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> inv_mask(x) end end)

    # inv_mask sets all existing bits to `0` and pads right with `1`-bits

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == inv_mask(%Pfx{bits: <<>>, maxlen: 0})

    # 1 bit
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == inv_mask(%Pfx{bits: <<>>, maxlen: 1})
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == inv_mask(%Pfx{bits: <<1::1>>, maxlen: 1})

    # some bits
    assert %Pfx{bits: <<0, -1::7>>, maxlen: 15} == inv_mask(%Pfx{bits: <<255>>, maxlen: 15})

    # all formats
    assert "0.0.0.255" == inv_mask("10.11.12.14/24")
    assert {{0, 0, 0, 127}, 32} == inv_mask({{1, 2, 3, 4}, 25})
    assert {0, 0, 0, 0} == inv_mask({1, 2, 3, 4})
  end

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

    # is_pfx as an actual guard
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
    refute f.("1.1.1.1")
    refute f.("acdc:1976::")
    refute f.([])
    refute f.({1, 2, 3, 4})
    refute f.({{1, 2, 3, 4}, 32})

    # more generic cases
    Enum.all?(@bad_representations, fn x -> refute(f.(x)) end)

    # lets end on a positive note
    Enum.all?(@ip4_representations, fn x -> assert(f.(new(x))) end)
    Enum.all?(@ip6_representations, fn x -> assert(f.(new(x))) end)
  end

  test "keep/2" do
    Enum.all?(@ip4_representations, fn x -> assert keep(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert keep(x, 0) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> keep(x, 0) end end)

    # more bad input
    assert_raise ArgumentError, fn -> keep("1.1.1.1", -1) end
    assert_raise ArgumentError, fn -> keep("1.1.1.1", 1.0) end

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == keep(%Pfx{bits: <<>>, maxlen: 0}, 1)

    # one bit
    assert %Pfx{bits: <<1::1>>, maxlen: 8} == keep(%Pfx{bits: <<1::1>>, maxlen: 8}, 1)

    # some bits
    assert %Pfx{bits: <<1::4>>, maxlen: 8} == keep(%Pfx{bits: <<16>>, maxlen: 8}, 4)
    assert %Pfx{bits: <<1>>, maxlen: 16} == keep(%Pfx{bits: <<1, 2>>, maxlen: 16}, 8)

    # count > pfx.bits => just keeps all bits
    assert %Pfx{bits: <<-1::128>>, maxlen: 128} == keep(%Pfx{bits: <<-1::128>>, maxlen: 128}, 512)

    # all representations
    assert "1.1.1.1" == keep("1.1.1.1", 32)
    assert "1.2.0.0/16" == keep("1.2.3.4", 16)
    assert {1, 2, 0, 0} == keep({1, 2, 3, 4}, 16)
    assert {{1, 2, 0, 0}, 16} == keep({{1, 2, 3, 4}, 32}, 16)
  end

  test "last/1" do
    Enum.all?(@ip4_representations, fn x -> assert last(x) end)
    Enum.all?(@ip6_representations, fn x -> assert last(x) end)

    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> last(x) end end)

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == last(%Pfx{bits: <<>>, maxlen: 0})

    # only one bit
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == last(%Pfx{bits: <<>>, maxlen: 1})

    # more bits
    assert %Pfx{bits: <<255, 255>>, maxlen: 16} == last(%Pfx{bits: <<255>>, maxlen: 16})

    # full address
    assert %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32} ==
             last(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32})

    # all formats
    assert "1.1.1.255" == last("1.1.1.0/24")
    assert "1.255.255.255" == last("1.0.0.0/8")
    assert "acdc:1976:ffff:ffff:ffff:ffff:ffff:ffff" == last("acdc:1976::/32")
    assert {{1, 2, 3, 255}, 32} == last({{1, 2, 3, 4}, 24})
  end

  test "link_local?/1" do
    # a bad representation will get you false everytime
    Enum.all?(@bad_representations, fn x -> refute link_local?(x) end)

    # ipv4 (almost all) link_local
    refute link_local?("169.254.0.0")
    refute link_local?("169.254.255.0")
    refute link_local?("169.254.255.255")
    assert link_local?("169.254.128.128")
    assert link_local?("0.0.0.0")
    assert link_local?("0.255.255.255")
    refute link_local?("1.0.0.0")
    refute link_local?("1.255.255.255")

    # ipv6 link locals
    assert link_local?(%Pfx{bits: <<0xFE80::16, 0::48, 0::64>>, maxlen: 128})
    assert link_local?(%Pfx{bits: <<0xFE80::16, 0::48, -1::64>>, maxlen: 128})

    # other formats
    assert link_local?("fe80::")
    assert link_local?("fe80:0:0:0:1:2:3:4")
    assert link_local?("fe80:0:0:0:ffff:ffff:ffff:ffff")
    refute link_local?({169, 254, 0, 0})
    refute link_local?({169, 254, 0, 255})
    refute link_local?({169, 254, 255, 0})
    refute link_local?({169, 254, 255, 255})
    assert link_local?({169, 254, 1, 0})
    assert link_local?({169, 254, 1, 255})
  end

  test "link_local/1" do
    Enum.all?(@ip6_representations, fn x -> assert nil == link_local(x) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> link_local(x) end
    end)
  end

  test "mask/1" do
    Enum.all?(@ip4_representations, fn x -> assert mask(x) end)
    Enum.all?(@ip6_representations, fn x -> assert mask(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> mask(x) end end)

    # mask sets all existing bits to `1` and pads right with `0`-bits

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == mask(%Pfx{bits: <<>>, maxlen: 0})

    # 1 bit
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == mask(%Pfx{bits: <<>>, maxlen: 1})
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == mask(%Pfx{bits: <<1::1>>, maxlen: 1})

    # some bits
    assert %Pfx{bits: <<255, 0::7>>, maxlen: 15} == mask(%Pfx{bits: <<255>>, maxlen: 15})
  end

  test "mask/2 applies mask to prefix" do
    Enum.all?(@ip4_representations, fn x -> assert mask(x, "255.0.0.0/8") end)
    Enum.all?(@ip6_representations, fn x -> assert mask(x, "ffff::/16") end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> mask(x, "255.255.255.0") end
    end)

    # mask requires prefix and mask to be of same type
    assert_raise ArgumentError, fn -> mask("1.2.3.4", "acdc::/16") end

    # mask with full address lengths
    assert "1.0.0.1" == mask("1.1.1.1", "255.0.0.255")
    assert "acdc:1976:0:0:0:0:0:0" == mask("acdc:1976:2021::", "acdc:1976::", trim: false)

    # trim defaults to true
    assert "1.1.1.0/24" == mask("1.1.1.1", "255.255.255.0")
    assert "1.1.1.0" == mask("1.1.1.1", "255.255.255.0", trim: false)
    assert "1.1.1.0" == mask("1.1.1.1", "255.255.255.0/24", trim: false)

    # inverts mask when asked
    assert "1.1.1.0/24" == mask("1.1.1.1", "0.0.0.255", inv_mask: true)
    assert "1.1.1.0" == mask("1.1.1.1", "0.0.0.255", inv_mask: true, trim: false)
    assert "10.16.0.0/14" == mask("10.16.1.1", "0.3.255.255", inv_mask: true)

    # representations
    assert {{1, 2, 0, 0}, 16} == mask({{1, 2, 3, 4}, 32}, "255.255.0.0")
    assert {{1, 2, 0, 0}, 16} == mask({{1, 2, 3, 4}, 32}, "255.255.0.0/16")
    assert {1, 2, 0, 0} == mask({1, 2, 3, 4}, {1, 2, 0, 0})

    assert %Pfx{bits: <<1, 2>>, maxlen: 32} ==
             mask(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}, %Pfx{bits: <<255, 255>>, maxlen: 32})
  end

  test "member/2" do
    Enum.all?(@ip4_representations, fn x -> assert member(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert member(x, 0) end)

    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> member(x, 0) end end)

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == member(%Pfx{bits: <<>>, maxlen: 0}, 0)
    # member wraps around
    assert %Pfx{bits: <<>>, maxlen: 0} == member(%Pfx{bits: <<>>, maxlen: 0}, 1)

    assert %Pfx{bits: <<1, 1, 1, 1>>, maxlen: 32} ==
             member(%Pfx{bits: <<1, 1, 1, 1>>, maxlen: 32}, 345)

    # some bits
    assert %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32} ==
             member(%Pfx{bits: <<1, 2, 3>>, maxlen: 32}, 4)

    # result mirrors format of first argument
    assert "1.2.3.255" == member("1.2.3.0/24", 255)
    assert "1.2.3.255" == member("1.2.0.0/16", 3 * 256 + 255)
    assert "1.1.1.1" == member("1.1.1.0/31", 1)
  end

  test "member?/2" do
    Enum.all?(@ip4_representations, fn x -> assert member?(x, x) end)
    Enum.all?(@ip6_representations, fn x -> assert member?(x, x) end)
    # member? wont raise, just says false
    Enum.all?(@bad_representations, fn x -> refute member?(x, x) end)

    # a prefix is always its own member
    pfx = %Pfx{bits: <<>>, maxlen: 16}
    assert true == member?(pfx, pfx)
    pfx = %Pfx{bits: <<-1::128>>, maxlen: 128}
    assert true == member?(pfx, pfx)
    pfx = %Pfx{bits: <<0::32>>, maxlen: 32}
    assert true == member?(pfx, pfx)
    assert true == member?({{1, 1, 1, 1}, 8}, "1.0.0.0/8")

    # member? accepts all formats
    assert true == member?("1.1.1.1", "1.1.1.1/32")
    assert true == member?("1.1.1.0", "1.1.1.0/31")
    assert true == member?("1.1.1.1", "1.1.1.0/31")
    assert true == member?("255.255.255.255", "0.0.0.0/0")

    assert true == member?({1, 1, 1, 1}, "1.0.0.0/8")
    assert true == member?({{1, 1, 1, 1}, 32}, "1.0.0.0/8")
  end

  test "multicast?/1" do
    Enum.all?(@bad_representations, fn x -> refute multicast?(x) end)

    # valid mcast addresses
    assert multicast?(%Pfx{bits: <<14::4, 0::28>>, maxlen: 32})
    assert multicast?(%Pfx{bits: <<14::4, -1::28>>, maxlen: 32})
  end

  test "multicast_decode/1" do
    Enum.all?(@ip4_representations, fn x -> assert nil == multicast_decode(x) end)
    Enum.all?(@ip6_representations, fn x -> assert nil == multicast_decode(x) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> multicast_decode(x) end
    end)

    # ipv4
    assert multicast_decode("224.0.0.1") == %{
             multicast_address: "224.0.0.1",
             protocol: :ipv4,
             rfc: %{multicast_prefix: "224.0.0.0/4", rfc: 1112}
           }

    # mirrors representation
    map = multicast_decode(%Pfx{bits: <<224, 0, 0, 1>>, maxlen: 32})
    assert map[:multicast_address] == %Pfx{bits: <<224, 0, 0, 1>>, maxlen: 32}
    assert map[:rfc][:multicast_prefix] == %Pfx{bits: <<14::4>>, maxlen: 32}

    assert multicast_decode("234.192.0.2") == %{
             multicast_address: "234.192.0.2",
             protocol: :ipv4,
             rfc: %{
               group_id: 2,
               multicast_prefix: "234.0.0.0/8",
               unicast_prefix: "192.0.2.0/24",
               rfc: 6034
             }
           }

    # mirrors representation
    map = multicast_decode(%Pfx{bits: <<234, 192, 0, 2>>, maxlen: 32})
    assert map[:multicast_address] == %Pfx{bits: <<234, 192, 0, 2>>, maxlen: 32}
    assert map[:rfc][:multicast_prefix] == %Pfx{bits: <<234>>, maxlen: 32}
    assert map[:rfc][:unicast_prefix] == %Pfx{bits: <<192, 0, 2>>, maxlen: 32}

    assert multicast_decode("233.22.30.1") == %{
             multicast_address: "233.22.30.1",
             protocol: :ipv4,
             rfc: %{
               as: 5662,
               local_bits: 1,
               multicast_prefix: "233.0.0.0/8",
               rfc: 3180
             }
           }

    # mirrors representation
    map = multicast_decode(%Pfx{bits: <<233, 22, 30, 1>>, maxlen: 32})
    assert map[:multicast_address] == %Pfx{bits: <<233, 22, 30, 1>>, maxlen: 32}
    assert map[:rfc][:multicast_prefix] == %Pfx{bits: <<233>>, maxlen: 32}

    # ipv6
    assert multicast_decode("ff71:340:2001:db8:beef:feed:0:f") == %{
             flags: {0, 1, 1, 1},
             multicast_address: "ff71:340:2001:db8:beef:feed:0:f",
             multicast_prefix: "ff70:0:0:0:0:0:0:0/12",
             protocol: :ipv6,
             rfc: %{
               group_id: 15,
               unicast_prefix: "2001:db8:beef:feed:0:0:0:0/64",
               plen: 64,
               reserved: 0,
               rfc: 3956,
               riid: 3,
               rp_prefix: "2001:db8:beef:feed:0:0:0:3"
             },
             scope: 1
           }

    # mirrors representation
    map =
      multicast_decode(%Pfx{
        bits:
          <<0xFF71::16, 0x340::16, 0x2001::16, 0xDB8::16, 0xBEEF::16, 0xFEED::16, 0::16, 0xF::16>>,
        maxlen: 128
      })

    assert map[:multicast_address] ==
             %Pfx{
               bits:
                 <<0xFF71::16, 0x340::16, 0x2001::16, 0xDB8::16, 0xBEEF::16, 0xFEED::16, 0::16,
                   0xF::16>>,
               maxlen: 128
             }

    assert map[:multicast_prefix] ==
             %Pfx{
               bits: <<0xFF7::12>>,
               maxlen: 128
             }

    assert map[:rfc][:unicast_prefix] ==
             %Pfx{
               bits: <<0x2001::16, 0xDB8::16, 0xBEEF::16, 0xFEED::16>>,
               maxlen: 128
             }

    assert map[:rfc][:rp_prefix] ==
             %Pfx{
               bits:
                 <<0x2001::16, 0xDB8::16, 0xBEEF::16, 0xFEED::16, 0::16, 0::16, 0::16, 3::16>>,
               maxlen: 128
             }

    assert multicast_decode("FF31:0030:3FFE:FFFF:0001::8") == %{
             flags: {0, 0, 1, 1},
             multicast_address: "ff31:30:3ffe:ffff:1:0:0:8",
             multicast_prefix: "ff30:0:0:0:0:0:0:0/12",
             protocol: :ipv6,
             rfc: %{
               group_id: 8,
               unicast_prefix: "3ffe:ffff:1:0:0:0:0:0/48",
               plen: 48,
               reserved: 0,
               rfc: 3306
             },
             scope: 1
           }

    # mirrors representation
    map =
      multicast_decode(%Pfx{
        bits: <<0xFF31::16, 0x0030::16, 0x3FFE::16, 0xFFFF::16, 0x0001::16, 0::16, 0::16, 8::16>>,
        maxlen: 128
      })

    assert map[:multicast_address] ==
             %Pfx{
               bits:
                 <<0xFF31::16, 0x0030::16, 0x3FFE::16, 0xFFFF::16, 1::16, 0::16, 0::16, 8::16>>,
               maxlen: 128
             }

    assert map[:multicast_prefix] ==
             %Pfx{bits: <<0xFF3::12>>, maxlen: 128}

    assert map[:rfc][:unicast_prefix] ==
             %Pfx{bits: <<0x3FFE::16, 0xFFFF::16, 1::16>>, maxlen: 128}
  end

  test "nat64_decode/1" do
    Enum.all?(@ip4_representations, fn x ->
      assert_raise ArgumentError, fn -> nat64_decode(x) end
    end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> nat64_decode(x) end
    end)
  end

  test "nat64_encode/2" do
    Enum.all?(@ip4_representations, fn x ->
      assert_raise ArgumentError, fn -> nat64_encode(x, x) end
    end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> nat64_encode(x, x) end
    end)
  end

  test "neighbor/1" do
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> neighbor(x) end end)

    # a real neighbor needs some real bits
    assert_raise ArgumentError, fn -> neighbor(%Pfx{bits: <<>>, maxlen: 0}) end

    # 1 bit
    assert %Pfx{bits: <<1::1>>, maxlen: 1} == neighbor(%Pfx{bits: <<0::1>>, maxlen: 1})
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == neighbor(%Pfx{bits: <<1::1>>, maxlen: 1})

    # more bits
    assert %Pfx{bits: <<254>>, maxlen: 16} == neighbor(%Pfx{bits: <<255>>, maxlen: 16})

    assert %Pfx{bits: <<255, 1::1>>, maxlen: 16} ==
             neighbor(%Pfx{bits: <<255, 0::1>>, maxlen: 16})

    # other formats
    assert "1.1.1.0/31" == neighbor("1.1.1.3/31")
    assert {{1, 2, 3, 4}, 30} == neighbor({{1, 2, 3, 0}, 30})
    assert "10.11.12.1" == neighbor("10.11.12.0")
  end

  test "network/1" do
    Enum.all?(@ip4_representations, fn x -> assert network(x) end)
    Enum.all?(@ip6_representations, fn x -> assert network(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> network(x) end end)

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 0} == network(%Pfx{bits: <<>>, maxlen: 0})

    # only one bit
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == network(%Pfx{bits: <<>>, maxlen: 1})

    # more bits
    assert %Pfx{bits: <<255, 0>>, maxlen: 16} == network(%Pfx{bits: <<255>>, maxlen: 16})

    # full address
    assert %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32} ==
             network(%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32})

    # all formats
    assert "1.1.1.0" == network("1.1.1.255/24")
    assert "acdc:1976:0:0:0:0:0:0" == network("acdc:1976::/32")
    assert {{1, 2, 3, 0}, 32} == network({{1, 2, 3, 4}, 24})
  end

  test "new/{1,2}" do
    # good args
    f = fn x -> assert new(x) end
    Enum.all?(@ip4_representations, f)
    Enum.all?(@ip6_representations, f)

    # bad args
    f = fn x -> assert_raise ArgumentError, fn -> new(x) end end
    Enum.all?(@bad_representations, f)
    assert_raise ArgumentError, fn -> new(<<>>, -1) end
    # bad eui-48's
    assert_raise ArgumentError, fn -> new("aa.bbcc-ddee.ff") end
    assert_raise ArgumentError, fn -> new("aa.bb:cc:dd:ee:ff") end

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

    # eui-48
    addr = %Pfx{bits: <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF>>, maxlen: 48}
    assert addr == new(addr)
    assert addr == new(<<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF>>, 48)
    assert addr == new("aa:bb:cc:dd:ee:ff")
    assert addr == new("aa-bb-cc-dd-ee-ff")
    assert addr == new("aabb.ccdd.eeff")
    assert addr == new("aa:bb.cc-dd.ee:ff")

    oui = %Pfx{bits: <<0xAA, 0xBB, 0xCC>>, maxlen: 48}
    assert oui == new(oui)
    assert oui == new("aa:bb:cc:dd:ee:ff/24")
    assert oui == new("aa-bb-cc-dd-ee-ff/24")
    assert oui == new("aabb.ccdd.eeff/24")
  end

  test "padr/1" do
    Enum.all?(@ip4_representations, fn x -> assert padr(x) end)
    Enum.all?(@ip6_representations, fn x -> assert padr(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padr(x) end end)

    # no bits
    assert %Pfx{bits: <<0::23>>, maxlen: 23} == padr(%Pfx{bits: <<>>, maxlen: 23})

    # some bits
    assert %Pfx{bits: <<255, 0::15>>, maxlen: 23} == padr(%Pfx{bits: <<255>>, maxlen: 23})
    assert %Pfx{bits: <<255, 0::120>>, maxlen: 128} == padr(%Pfx{bits: <<255>>, maxlen: 128})

    # same representation for results
    assert "1.0.0.0" == padr("1.0.0.0/8")
    assert {1, 0, 0, 0} == padr({1, 0, 0, 0})
    assert {{1, 0, 0, 0}, 32} == padr({{1, 0, 0, 0}, 8})
  end

  test "padr/2" do
    Enum.all?(@ip4_representations, fn x -> assert padr(x, 0) end)
    Enum.all?(@ip4_representations, fn x -> assert padr(x, 1) end)
    Enum.all?(@ip6_representations, fn x -> assert padr(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert padr(x, 1) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padr(x, 0) end end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padr(x, 1) end end)

    # bad input
    assert_raise ArgumentError, fn -> padr("1.0.0.0/8", -1) end

    # no bits
    assert %Pfx{bits: <<0::23>>, maxlen: 23} == padr(%Pfx{bits: <<>>, maxlen: 23}, 0)
    assert %Pfx{bits: <<-1::23>>, maxlen: 23} == padr(%Pfx{bits: <<>>, maxlen: 23}, 1)

    # some bits
    assert %Pfx{bits: <<255, 0::15>>, maxlen: 23} == padr(%Pfx{bits: <<255>>, maxlen: 23}, 0)
    assert %Pfx{bits: <<255, -1::15>>, maxlen: 23} == padr(%Pfx{bits: <<255>>, maxlen: 23}, 1)
    assert %Pfx{bits: <<255, 0::120>>, maxlen: 128} == padr(%Pfx{bits: <<255>>, maxlen: 128}, 0)
    assert %Pfx{bits: <<255, -1::120>>, maxlen: 128} == padr(%Pfx{bits: <<255>>, maxlen: 128}, 1)

    # same representation for results
    assert "1.2.3.4" == padr("1.2.3.4", 0)
    assert "1.2.3.4" == padr("1.2.3.4", 1)
    assert "1.0.0.0" == padr("1.0.0.0/8", 0)
    assert "1.255.255.255" == padr("1.0.0.0/8", 1)
    assert {1, 0, 0, 0} == padr({1, 0, 0, 0}, 0)
    assert {1, 0, 0, 0} == padr({1, 0, 0, 0}, 1)
    assert {{1, 0, 0, 0}, 32} == padr({{1, 0, 0, 0}, 8}, 0)
    assert {{1, 255, 255, 255}, 32} == padr({{1, 0, 0, 0}, 8}, 1)
  end

  test "padr/3" do
    Enum.all?(@ip4_representations, fn x -> assert padr(x, 0, 0) end)
    Enum.all?(@ip4_representations, fn x -> assert padr(x, 1, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert padr(x, 0, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert padr(x, 1, 0) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> padr(x, 0, 0) end
    end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> padr(x, 1, 0) end
    end)

    # bad input
    assert_raise ArgumentError, fn -> padr("1.0.0.0/8", -1, 0) end
    assert_raise ArgumentError, fn -> padr("1.0.0.0/8", 0, -1) end

    # no bits padded
    assert %Pfx{bits: <<>>, maxlen: 23} == padr(%Pfx{bits: <<>>, maxlen: 23}, 0, 0)
    assert %Pfx{bits: <<>>, maxlen: 23} == padr(%Pfx{bits: <<>>, maxlen: 23}, 1, 0)

    # all bits padded
    assert %Pfx{bits: <<0::23>>, maxlen: 23} == padr(%Pfx{bits: <<>>, maxlen: 23}, 0, 23)
    assert %Pfx{bits: <<-1::23>>, maxlen: 23} == padr(%Pfx{bits: <<>>, maxlen: 23}, 1, 23)

    # some bits padded
    assert %Pfx{bits: <<255, 0>>, maxlen: 23} == padr(%Pfx{bits: <<255>>, maxlen: 23}, 0, 8)
    assert %Pfx{bits: <<255, 255>>, maxlen: 23} == padr(%Pfx{bits: <<255>>, maxlen: 23}, 1, 8)

    assert %Pfx{bits: <<255, 0::1>>, maxlen: 23} == padr(%Pfx{bits: <<255>>, maxlen: 23}, 0, 1)
    assert %Pfx{bits: <<255, 1::1>>, maxlen: 23} == padr(%Pfx{bits: <<255>>, maxlen: 23}, 1, 1)

    # padding is clipped to maxlen
    assert %Pfx{bits: <<255, -1::15>>, maxlen: 23} ==
             padr(%Pfx{bits: <<255>>, maxlen: 23}, 1, 500)

    assert %Pfx{bits: <<255, 0::120>>, maxlen: 128} ==
             padr(%Pfx{bits: <<255>>, maxlen: 128}, 0, 500)

    assert %Pfx{bits: <<255, -1::120>>, maxlen: 128} ==
             padr(%Pfx{bits: <<255>>, maxlen: 128}, 1, 300)

    # same representation for results
    assert "1.2.3.4" == padr("1.2.3.4", 0, 32)
    assert "1.2.3.4" == padr("1.2.3.4", 1, 32)
    assert "1.0.0.0" == padr("1.0.0.0/8", 0, 24)
    assert "1.255.255.255" == padr("1.0.0.0/8", 1, 24)
    assert {1, 0, 0, 0} == padr({1, 0, 0, 0}, 0, 1)
    assert {1, 0, 0, 0} == padr({1, 0, 0, 0}, 1, 1)
    assert {{1, 0, 0, 0}, 32} == padr({{1, 0, 0, 0}, 8}, 0, 24)
    assert {{1, 255, 255, 255}, 32} == padr({{1, 0, 0, 0}, 8}, 1, 24)
  end

  test "padl/1" do
    Enum.all?(@ip4_representations, fn x -> assert padl(x) end)
    Enum.all?(@ip6_representations, fn x -> assert padl(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padl(x) end end)

    # no bits
    assert %Pfx{bits: <<0::23>>, maxlen: 23} == padl(%Pfx{bits: <<>>, maxlen: 23})

    # some bits
    assert %Pfx{bits: <<0::15, 255>>, maxlen: 23} == padl(%Pfx{bits: <<255>>, maxlen: 23})
    assert %Pfx{bits: <<0::120, 255>>, maxlen: 128} == padl(%Pfx{bits: <<255>>, maxlen: 128})

    # same representation for results
    assert "0.0.0.1" == padl("1.0.0.0/8")
    assert {1, 0, 0, 0} == padl({1, 0, 0, 0})
    assert {{0, 0, 0, 1}, 32} == padl({{1, 0, 0, 0}, 8})
  end

  test "padl/2" do
    Enum.all?(@ip4_representations, fn x -> assert padl(x, 0) end)
    Enum.all?(@ip4_representations, fn x -> assert padl(x, 1) end)
    Enum.all?(@ip6_representations, fn x -> assert padl(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert padl(x, 1) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padl(x, 0) end end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> padl(x, 1) end end)

    # bad input
    assert_raise ArgumentError, fn -> padl("1.0.0.0/8", -1) end

    # no bits
    assert %Pfx{bits: <<0::23>>, maxlen: 23} == padl(%Pfx{bits: <<>>, maxlen: 23}, 0)
    assert %Pfx{bits: <<-1::23>>, maxlen: 23} == padl(%Pfx{bits: <<>>, maxlen: 23}, 1)

    # some bits
    assert %Pfx{bits: <<0::15, 255>>, maxlen: 23} == padl(%Pfx{bits: <<255>>, maxlen: 23}, 0)
    assert %Pfx{bits: <<-1::15, 255>>, maxlen: 23} == padl(%Pfx{bits: <<255>>, maxlen: 23}, 1)
    assert %Pfx{bits: <<0::120, 255>>, maxlen: 128} == padl(%Pfx{bits: <<255>>, maxlen: 128}, 0)
    assert %Pfx{bits: <<-1::120, 255>>, maxlen: 128} == padl(%Pfx{bits: <<255>>, maxlen: 128}, 1)

    # same representation for results
    assert "1.2.3.4" == padl("1.2.3.4", 0)
    assert "1.2.3.4" == padl("1.2.3.4", 1)
    assert "0.0.0.1" == padl("1.0.0.0/8", 0)
    assert "255.255.255.1" == padl("1.0.0.0/8", 1)
    assert {1, 0, 0, 0} == padl({1, 0, 0, 0}, 0)
    assert {1, 0, 0, 0} == padl({1, 0, 0, 0}, 1)
    assert {{0, 0, 0, 1}, 32} == padl({{1, 0, 0, 0}, 8}, 0)
    assert {{255, 255, 255, 1}, 32} == padl({{1, 0, 0, 0}, 8}, 1)
  end

  test "padl/3" do
    Enum.all?(@ip4_representations, fn x -> assert padl(x, 0, 0) end)
    Enum.all?(@ip4_representations, fn x -> assert padl(x, 1, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert padl(x, 0, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert padl(x, 1, 0) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> padl(x, 0, 0) end
    end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> padl(x, 1, 0) end
    end)

    # bad input
    assert_raise ArgumentError, fn -> padl("1.0.0.0/8", -1, 0) end
    assert_raise ArgumentError, fn -> padl("1.0.0.0/8", 0, -1) end

    # no bits padded
    assert %Pfx{bits: <<>>, maxlen: 23} == padl(%Pfx{bits: <<>>, maxlen: 23}, 0, 0)
    assert %Pfx{bits: <<>>, maxlen: 23} == padl(%Pfx{bits: <<>>, maxlen: 23}, 1, 0)

    # all bits padded
    assert %Pfx{bits: <<0::23>>, maxlen: 23} == padl(%Pfx{bits: <<>>, maxlen: 23}, 0, 23)
    assert %Pfx{bits: <<-1::23>>, maxlen: 23} == padl(%Pfx{bits: <<>>, maxlen: 23}, 1, 23)

    # some bits padded
    assert %Pfx{bits: <<0, 255>>, maxlen: 23} == padl(%Pfx{bits: <<255>>, maxlen: 23}, 0, 8)
    assert %Pfx{bits: <<255, 255>>, maxlen: 23} == padl(%Pfx{bits: <<255>>, maxlen: 23}, 1, 8)

    assert %Pfx{bits: <<0::1, 255>>, maxlen: 23} == padl(%Pfx{bits: <<255>>, maxlen: 23}, 0, 1)
    assert %Pfx{bits: <<1::1, 255>>, maxlen: 23} == padl(%Pfx{bits: <<255>>, maxlen: 23}, 1, 1)

    # padding is clipped to maxlen
    assert %Pfx{bits: <<-1::15, 255>>, maxlen: 23} ==
             padl(%Pfx{bits: <<255>>, maxlen: 23}, 1, 500)

    assert %Pfx{bits: <<0::120, 255>>, maxlen: 128} ==
             padl(%Pfx{bits: <<255>>, maxlen: 128}, 0, 500)

    assert %Pfx{bits: <<-1::120, 255>>, maxlen: 128} ==
             padl(%Pfx{bits: <<255>>, maxlen: 128}, 1, 300)

    # same representation for results
    assert "1.2.3.4" == padl("1.2.3.4", 0, 32)
    assert "1.2.3.4" == padl("1.2.3.4", 1, 32)
    assert "0.0.0.1" == padl("1.0.0.0/8", 0, 24)
    assert "255.255.255.1" == padl("1.0.0.0/8", 1, 24)
    assert {1, 0, 0, 0} == padl({1, 0, 0, 0}, 0, 1)
    assert {1, 0, 0, 0} == padl({1, 0, 0, 0}, 1, 1)
    assert {{0, 0, 0, 1}, 32} == padl({{1, 0, 0, 0}, 8}, 0, 24)
    assert {{255, 255, 255, 1}, 32} == padl({{1, 0, 0, 0}, 8}, 1, 24)
  end

  test "partition/2" do
    assert_raise ArgumentError, fn -> partition(%Pfx{bits: <<255>>, maxlen: 4}, 1) end
    assert_raise ArgumentError, fn -> partition(%Pfx{bits: <<255>>, maxlen: 8.0}, 1) end

    # try to use too many bits to partition
    assert_raise ArgumentError, fn -> partition(%Pfx{bits: <<255>>, maxlen: 16}, 17) end

    # no bits left
    assert [%Pfx{bits: <<>>, maxlen: 0}] == partition(%Pfx{bits: <<>>, maxlen: 0}, 0)
    assert [%Pfx{bits: <<255>>, maxlen: 8}] == partition(%Pfx{bits: <<255>>, maxlen: 8}, 8)
    assert [%Pfx{bits: <<255>>, maxlen: 16}] == partition(%Pfx{bits: <<255>>, maxlen: 16}, 8)

    # results mirror format of argument
    assert ["1.1.1.0", "1.1.1.1"] == partition("1.1.1.0/31", 32)
    assert [{{1, 1, 1, 0}, 32}, {{1, 1, 1, 1}, 32}] == partition({{1, 1, 1, 0}, 31}, 32)
    assert [{1, 1, 1, 1}] == partition({1, 1, 1, 1}, 32)

    assert 1 == partition("1.1.1.0", 32) |> length()
    assert 1 == partition("1.1.1.0/32", 32) |> length()
    assert 2 == partition("1.1.1.0/24", 25) |> length()
    assert 256 == partition("1.1.1.0/24", 32) |> length()
    assert 65536 == partition("acdc::1976/112", 128) |> length()
  end

  test "pfxlen/1" do
    for len <- 0..32 do
      assert len == pfxlen("1.2.3.4/#{len}")
      assert len == pfxlen({{1, 2, 3, 4}, len})
      assert len == new("1.2.3.4/#{len}") |> pfxlen()
    end

    for len <- 0..128 do
      assert len == pfxlen("::/#{len}")
      assert len == pfxlen({{1, 2, 3, 4, 5, 6, 7, 8}, len})
      assert len == new("::/#{len}") |> pfxlen()
    end

    for len <- 0..48 do
      assert len == pfxlen("11:22:33:44:55:66/#{len}")
      assert len == from_mac("11:22:33:44:55:66/#{len}") |> pfxlen()
    end

    for len <- 0..64 do
      assert len == pfxlen("11:22:33:44:55:66:77:88/#{len}")
      assert len == from_mac("11:22:33:44:55:66:77:88/#{len}") |> pfxlen()
    end

    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> pfxlen(x) end end)
  end

  test "parse/1" do
    Enum.all?(@ip4_representations, fn x -> assert :ok == parse(x) |> elem(0) end)
    Enum.all?(@ip6_representations, fn x -> assert :ok == parse(x) |> elem(0) end)
    Enum.all?(@bad_representations, fn x -> assert {:error, :einvalid} == parse(x) end)
  end

  test "parse/2" do
    Enum.all?(@ip4_representations, fn x -> assert :ok == parse(x, nil) |> elem(0) end)
    Enum.all?(@ip6_representations, fn x -> assert :ok == parse(x, nil) |> elem(0) end)
    Enum.all?(@bad_representations, fn x -> assert nil == parse(x, nil) end)
    Enum.all?(@bad_representations, fn x -> assert :nok == parse(x, :nok) end)
    Enum.all?(@bad_representations, fn x -> assert "err" == parse(x, "err") end)
  end

  test "remove/3" do
    Enum.all?(@ip4_representations, fn x -> assert remove(x, 0, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert remove(x, 0, 0) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> remove(x, 0, 0) end
    end)

    # position must be in range -bsize .. bsize-1
    assert_raise ArgumentError, fn -> remove("1.1.1.1", 32, 0) end
    assert_raise ArgumentError, fn -> remove("1.1.1.1", -33, 0) end

    # from front
    assert "2.3.0.0/16" == remove("1.2.3.0/24", 0, 8)
    assert "2.3.0.0/16" == remove("1.2.3.0/24", 7, -8)
    assert "2.3.0.0/16" == remove("1.2.3.0/24", -24, 8)
    assert "2.3.0.0/16" == remove("1.2.3.0/24", -16, -8)

    # from the end
    assert "1.2.0.0/16" == remove("1.2.3.0/24", 16, 8)
    assert "1.2.0.0/16" == remove("1.2.3.0/24", 23, -8)
    assert "1.2.0.0/16" == remove("1.2.3.0/24", -8, 8)
    assert "1.2.0.0/16" == remove("1.2.3.0/24", -1, -8)

    # somewhere in the middle
    assert "1.2.4.0/24" == remove("1.2.3.4", 16, 8)
    assert "1.3.4.0/24" == remove("1.2.3.4", 15, -8)

    # silently clip len when removing all bits
    assert "0.0.0.0/0" == remove("255.255.255.255", 0, 200)
    assert "0.0.0.0/0" == remove("255.255.255.255", -32, 200)
    assert "0.0.0.0/0" == remove("255.255.255.255", -1, -200)

    # also removes single bits
    assert "0.0.0.0/7" == remove("128.0.0.0/8", 0, 1)
    assert "255.255.255.254/31" == remove("255.255.255.255", -1, 1)
    assert "255.255.255.254/31" == remove("255.255.255.255", -31, -1)

    # representations
    assert %Pfx{bits: <<1, 2, 3>>, maxlen: 32} ==
             remove(%Pfx{bits: <<1, 2, 3, 1::1>>, maxlen: 32}, -1, 1)

    assert {{1, 2, 0, 0}, 16} == remove({{1, 2, 3, 0}, 24}, 16, 8)
    assert {1, 2, 0, 0} == remove({1, 2, 3, 0}, 16, 8)
  end

  test "sibling/2" do
    Enum.all?(@ip4_representations, fn x -> assert sibling(x, 0) end)
    Enum.all?(@ip6_representations, fn x -> assert sibling(x, 0) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> sibling(x, 0) end
    end)

    # a prefix is its own sibling at distance 0
    assert %Pfx{bits: <<1, 2, 3, 4, 5>>, maxlen: 48} ==
             sibling(%Pfx{bits: <<1, 2, 3, 4, 5>>, maxlen: 48}, 0)

    # result mirrors format of argument
    assert "1.1.1.1" == sibling("1.1.1.1", 0)
    assert "255.255.255.255" == sibling("0.0.0.0", -1)
    assert "0.0.0.0" == sibling("255.255.255.255", 1)

    assert {1, 1, 1, 1} == sibling({1, 1, 1, 1}, 0)
    assert {1, 1, 1, 0} == sibling({1, 1, 1, 1}, -1)
    assert {1, 1, 1, 2} == sibling({1, 1, 1, 1}, 1)

    assert "1.1.1.0/24" == sibling("1.1.1.0/24", 0)
    assert "1.1.2.0/24" == sibling("1.1.1.0/24", 1)
  end

  test "size/1" do
    Enum.all?(@ip4_representations, fn x -> assert size(x) end)
    Enum.all?(@ip6_representations, fn x -> assert size(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> size(x) end end)

    # no bits, but the empty prefix counts as well
    assert 1 == size(%Pfx{bits: <<>>, maxlen: 0})

    # no bits left, so again size of 1
    assert 1 == size(%Pfx{bits: <<255>>, maxlen: 8})

    # some bits left
    assert 16 == size(%Pfx{bits: <<255>>, maxlen: 12})
    assert 256 == size(%Pfx{bits: <<1, 2, 3>>, maxlen: 32})
    assert 65536 == size(%Pfx{bits: <<1, 2>>, maxlen: 32})

    # accepts all formats
    assert 1 == size("1.1.1.1")
    assert 1 == size({1, 1, 1, 1})
    assert 1 == size({{1, 1, 1, 1}, 32})
    assert 2 == size("acdc:1976::/127")
    assert 256 == size("1.1.1.0/24")
    assert 256 == size({{0, 0, 0, 0}, 24})
  end

  test "teredo?/1" do
    Enum.all?(@bad_representations, fn x -> refute teredo?(x) end)

    # no bits
    refute teredo?(%Pfx{bits: <<>>, maxlen: 0})

    # ipv4 is never a teredo address
    refute teredo?(%Pfx{bits: <<0, 0, 0, 0>>, maxlen: 32})
    refute teredo?(%Pfx{bits: <<255, 255, 255, 255>>, maxlen: 32})
    refute teredo?(%Pfx{bits: <<>>, maxlen: 32})
    refute teredo?(%Pfx{bits: <<0x2001::16, 0::16>>, maxlen: 32})

    # ipv6 only 1 segment
    assert teredo?(%Pfx{bits: <<0x2001::16, 0::16>>, maxlen: 128})
    assert teredo?(%Pfx{bits: <<0x2001::16, 0::16, 0::96>>, maxlen: 128})
    assert teredo?(%Pfx{bits: <<0x2001::16, 0::16, 0::48, -1::48>>, maxlen: 128})
    assert teredo?(%Pfx{bits: <<0x2001::16, 0::16, -1::48, 0::48>>, maxlen: 128})
    assert teredo?(%Pfx{bits: <<0x2001::16, 0::16, -1::96>>, maxlen: 128})

    # other formats
    refute teredo?("1.1.1.1")
    refute teredo?("0.0.0.0/0")
    refute teredo?("acdc:1976::")
    assert teredo?("2001:0::")
    assert teredo?("2001:0:ffff:ffff:ffff:ffff:ffff:ffff")
    assert teredo?("2001:0:ffff:0:ffff:0:ffff:0")
    assert teredo?("2001:0:1:2:3:4:5:6")
  end

  test "teredo_encode/4 - TODO" do
  end

  test "teredo_decode/1" do
    Enum.all?(@ip4_representations, fn x -> assert nil == teredo_decode(x) end)
    Enum.all?(@ip6_representations, fn x -> assert nil == teredo_decode(x) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> teredo_decode(x) end
    end)

    server = new("1.2.3.4")
    client = new("10.10.10.10") |> bnot()
    port = Bitwise.bnot(33000)
    flags = <<1::1, 0::15>>

    addr = %Pfx{
      bits: <<0x2001::16, 0x0::16, server.bits::bits, flags::bits, port::16, client.bits::bits>>,
      maxlen: 128
    }

    map = teredo_decode(addr)
    assert map.server == %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}
    assert map.client == %Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}
    assert map.port == 33000
    assert map.flags == {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    assert map.prefix == addr

    # follows representation of addr for client/server
    map = teredo_decode("#{addr}")
    assert map.server == "1.2.3.4"
    assert map.client == "10.10.10.10"
    assert map.port == 33000
    assert map.flags == {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    assert map.prefix == "#{addr}"

    # follows representation of addr for client/server
    map = teredo_decode(digits(addr, 16))
    assert map.server == {{1, 2, 3, 4}, 32}
    assert map.client == {{10, 10, 10, 10}, 32}
    assert map.port == 33000
    assert map.flags == {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    assert map.prefix == digits(addr, 16)
  end

  test "trim/1 removes all trailing zero's" do
    Enum.all?(@ip4_representations, fn x -> assert trim(x) end)
    Enum.all?(@ip6_representations, fn x -> assert trim(x) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> trim(x) end
    end)

    assert "1.1.1.0/24" == trim("1.1.1.0")

    # representations
    assert "1.1.0.0/16" == trim("1.1.0.0/30")
    assert {{1, 1, 1, 0}, 24} == trim({{1, 1, 1, 0}, 32})
    assert %Pfx{bits: <<1, 1>>, maxlen: 32} == trim(%Pfx{bits: <<1, 1, 0, 0>>, maxlen: 32})
    assert {1, 1, 0, 0} == trim({1, 1, 0, 0})
  end

  test "undigits/2" do
    # bad input
    assert_raise ArgumentError, fn -> undigits("1.1.1.1", 8) end
    assert_raise ArgumentError, fn -> undigits({1, 1, 1, 1}, 8) end
    assert_raise ArgumentError, fn -> undigits({{1, 1, 1, 1}, 32}, 1.0) end
    assert_raise ArgumentError, fn -> undigits({{1, 1, 1, 1}, 32}, 0) end
    assert_raise ArgumentError, fn -> undigits({{1, 1.0, 1, 1}, 32}, 8) end

    # no bits
    assert %Pfx{bits: <<>>, maxlen: 32} == undigits({{0, 0, 0, 0}, 0}, 8)

    # with bits
    assert %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32} == undigits({{1, 2, 3, 4}, 32}, 8)
    assert %Pfx{bits: <<1, 2>>, maxlen: 16} == undigits({{1, 2}, 16}, 8)
  end

  test "valid?/2" do
    Enum.all?(@ip4_representations, fn x -> assert valid?(x) end)
    Enum.all?(@ip6_representations, fn x -> assert valid?(x) end)
    Enum.all?(@bad_representations, fn x -> refute valid?(x) end)

    # no bits
    assert valid?(%Pfx{bits: <<>>, maxlen: 0})
  end

  test "String.Chars" do
    # no mask for full addresses
    assert "1.2.3.4" == "#{%Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}}"

    assert "acdc:1976:0:0:0:0:0:0" ==
             "#{%Pfx{bits: <<0xACDC::16, 0x1976::16, 0::96>>, maxlen: 128}}"

    assert "acdc:1976:ffff:ffff:ffff:ffff:ffff:ffff" ==
             "#{%Pfx{bits: <<0xACDC::16, 0x1976::16, -1::96>>, maxlen: 128}}"
  end
end
