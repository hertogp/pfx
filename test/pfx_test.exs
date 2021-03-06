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

  test "guards" do
    assert is_comparable(new("1.1.1.1"), new("2.2.2.2/24"))
  end

  test "address/1" do
    Enum.all?(@ip4_representations, fn x -> assert address(x) end)
    Enum.all?(@ip6_representations, fn x -> assert address(x) end)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> address(x) end end)

    # results mirror the argument
    assert "1.2.3.4" == address("1.2.3.4/0")
    assert "1.2.3.4" == address("1.2.3.4/9")
    assert "1.2.3.4" == address("1.2.3.4/32")
    assert {1, 2, 3, 4} == address({{1, 2, 3, 4}, 16})
    assert {1, 2, 3, 4, 5, 6, 7, 8} == address({{1, 2, 3, 4, 5, 6, 7, 8}, 64})

    # these have no effect
    assert {1, 2, 3, 4} == address({1, 2, 3, 4})
    assert {1, 2, 3, 4, 5, 6, 7, 8} == address({1, 2, 3, 4, 5, 6, 7, 8})
    assert %Pfx{bits: <<1, 2, 3>>, maxlen: 32} == address(%Pfx{bits: <<1, 2, 3>>, maxlen: 32})
    assert %Pfx{bits: <<>>, maxlen: 128} == address(%Pfx{bits: <<>>, maxlen: 128})
  end

  @tag tst: "band"
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

    # pos is not an int
    assert_raise ArgumentError, fn -> bit(%Pfx{bits: <<255>>, maxlen: 16}, [6]) end
    assert_raise ArgumentError, fn -> bit(%Pfx{bits: <<255>>, maxlen: 16}, "6") end

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

  test "bits/2" do
    Enum.all?(@ip4_representations, fn x -> assert bits(x, [{0, 0}]) end)
    Enum.all?(@ip6_representations, fn x -> assert bits(x, [{0, 0}]) end)

    pfx = %Pfx{bits: <<0, 0, 128, 1>>, maxlen: 32}
    assert <<128>> == bits(pfx, [{16, 8}])
    assert <<>> == bits(pfx, [])

    # pfx must be understood by new/1
    assert_raise ArgumentError, fn -> bits("xyz", [{0, 0}]) end
    # out of range
    assert_raise ArgumentError, fn -> bits(pfx, [{24, 16}]) end

    # pfx can be any kind of prefix
    assert <<128>> == bits(new(<<0, 128>>, 16), [{8, 8}])
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

    # position and length must be integers
    assert <<128>> == bits(pfx, 16, 8)
    assert_raise ArgumentError, fn -> bits(pfx, 16.0, 8) end
    assert_raise ArgumentError, fn -> bits(pfx, 16, 8.0) end
    assert_raise ArgumentError, fn -> bits(pfx, [16], 8) end
    assert_raise ArgumentError, fn -> bits(pfx, 16, [8]) end

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

    # n must be an integer
    assert "4.1.2.3" == brot("1.2.3.4", 8)
    assert_raise ArgumentError, fn -> brot("1.2.3.4", 8.0) end
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
    assert "1.2.3.4" == bsl("1.2.3.4", 0)
    assert "2.3.4.0" == bsl("1.2.3.4", 8)
    assert "2.3.0.0/24" == bsl("1.2.3.4/24", 8)
    assert {2, 3, 4, 0} == bsl({1, 2, 3, 4}, 8)
    assert {0, 1, 2, 3} == bsl({1, 2, 3, 4}, -8)

    # shift must be an integer
    assert_raise ArgumentError, fn -> bsl("1.2.3.4", 8.0) end
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

    # shift must be an integer
    assert_raise ArgumentError, fn -> bsr("1.2.3.4", 8.0) end
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
    assert 65_535 - 255 == cast(%Pfx{bits: <<255>>, maxlen: 16})
  end

  test "compare/2" do
    Enum.all?(@ip4_representations, fn x -> assert compare(x, x) end)
    Enum.all?(@ip6_representations, fn x -> assert compare(x, x) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> compare(x, x) end
    end)

    # full prefixes
    assert :lt == compare("1.1.1.1", "1.1.1.2")
    assert :gt == compare("1.1.1.1", "1.1.1.0")
    assert :eq == compare("1.1.1.1", "1.1.1.1")

    # networks
    assert :lt == compare("10.11.12.0/24", "10.11.0.0/16")
    assert :gt == compare("10.11.0.0/16", "10.11.12.0/24")
    assert :eq == compare("10.11.0.0/16", "10.11.0.0/16")

    # mixed types are ok too
    assert :lt == compare("1.1.1.1", "acdc::")
  end

  test "contrast/2" do
    Enum.all?(@ip4_representations, fn x -> assert :equal == contrast(x, x) end)
    Enum.all?(@ip6_representations, fn x -> assert :equal == contrast(x, x) end)
    Enum.all?(@bad_representations, fn x -> assert :einvalid == contrast(x, x) end)

    # needs args to be of same type
    assert :incompatible == contrast("1.1.1.1", "acdc::")
    # need to be valid
    assert :einvalid == contrast("1.1.1.400", "1.1.1.1")
    assert :einvalid == contrast("acdc::defg", "acdc::1")

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

    # width must be positive integer
    assert_raise ArgumentError, fn -> digits("1.2.3.4", 1.0) end
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

  test "eui64_decode" do
    assert_raise ArgumentError, fn -> new("1.1.1.1") |> eui64_decode() end
    assert_raise ArgumentError, fn -> eui64_decode("1.1.1.1") end
  end

  test "eui64_encode" do
    assert_raise ArgumentError, fn -> new("1.1.1.1") |> eui64_encode() end
    assert_raise ArgumentError, fn -> eui64_encode("1.1.1.1") end
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
    assert "acdc:1976::" == first("acdc:1976::/32")
    assert {{1, 2, 3, 0}, 32} == first({{1, 2, 3, 4}, 24})
  end

  test "flip/2" do
    # flip errors out on invalid bit positions
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> flip(x, 0) end end)

    # out of range
    assert_raise ArgumentError, fn -> flip("0.0.0.0/0", 0) end
    assert_raise ArgumentError, fn -> flip(%Pfx{bits: <<255>>, maxlen: 16}, 16) end
    assert_raise ArgumentError, fn -> flip(%Pfx{bits: <<255>>, maxlen: 16}, -17) end

    # position must be an integer
    assert "128.0.0.0" == flip("0.0.0.0", 0)
    assert_raise ArgumentError, fn -> flip("0.0.0.0", 0.0) end

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
    assert 65_536 == hosts("10.10.0.0/16") |> length()

    # all representations
    assert 16 == hosts({{10, 10, 10, 0}, 28}) |> length()
    assert 256 == hosts({{10, 10, 10, 0}, 24}) |> length()
    assert 65_536 == hosts({{10, 10, 10, 10}, 16}) |> length()

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

    # nth must be an integer
    assert_raise ArgumentError, fn -> host("1.1.1.0/25", 63.0) end
  end

  test "iana_special/2" do
    assert_raise ArgumentError, fn -> iana_special("1.1.1.400") end

    # not registered, means empty property map
    assert nil == iana_special("1.1.1.1")
    assert nil == iana_special("aa-bb-cc-dd-ee-ff")

    # registered, return property map
    assert iana_special("192.168.0.0/16") == %{
             allocation: "1996-02",
             destination: true,
             forward: true,
             global: false,
             name: "private-use",
             prefix: "192.168.0.0/16",
             reserved: false,
             source: true,
             spec: ["rfc1918"],
             termination: :na
           }

    assert iana_special("2001::1") == %{
             allocation: "2006-01",
             destination: true,
             forward: true,
             global: :na,
             name: "teredo",
             prefix: "2001::/32",
             reserved: false,
             source: true,
             spec: ["rfc4380", "rfc8190"],
             termination: :na
           }

    # get an individual property
    assert true == iana_special("10.10.10.10", :source)
    assert true == iana_special("10.10.10.10", :destination)
    assert true == iana_special("10.10.10.10", :forward)
    assert false == iana_special("10.10.10.10", :global)
    assert false == iana_special("10.10.10.10", :reserved)
    assert "1996-02" == iana_special("10.10.10.10", :allocation)
    assert ["rfc1918"] == iana_special("10.10.10.10", :spec)
    assert "10.0.0.0/8" == iana_special("10.10.10.10", :prefix)
    assert "private-use" == iana_special("10.10.10.10", :name)
    assert :na == iana_special("10.10.10.10", :termination)

    # multiple prefixes are split into their own entries
    assert "192.0.0.170/32" == iana_special("192.0.0.170", :prefix)
    assert "192.0.0.171/32" == iana_special("192.0.0.171", :prefix)
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
    assert "1.1.1.1" == insert("1.1.1.1", <<>>, 8)
    assert_raise ArgumentError, fn -> insert("1.1.1.1", <<>>, 8.0) end

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

  test "invert/1" do
    # this function simply calls bnot
    assert "0.0.255.255" == invert("255.255.0.0")
    assert_raise ArgumentError, fn -> invert("1.1.1.329") end
  end

  test "is_pfx/1" do
    # handle zero bits
    assert is_pfx(%Pfx{bits: <<>>, maxlen: 0})
    assert is_pfx(%Pfx{bits: <<>>, maxlen: 10_000})

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
    assert link_local?("fe80::1:2:3:4")
    assert link_local?("fe80::ffff:ffff:ffff:ffff")
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

  test "marshall/2" do
    # when x is not a Pfx.t, it is returned unchanged
    Enum.all?(@ip4_representations, fn x -> assert x == marshall(x, x) end)
    Enum.all?(@ip6_representations, fn x -> assert x == marshall(x, x) end)
    Enum.all?(@bad_representations, fn x -> assert x == marshall(x, x) end)
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
    assert "acdc:1976::" == mask("acdc:1977:2021::", "acdc:1976::", trim: false)

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

  test "minimize/1" do
    l = minimize(@ip4_representations)
    assert length(l) > 0

    # raises on invalid input
    assert_raise ArgumentError, fn -> minimize(["1.1.1.1", "1.1.1.333"]) end
    assert_raise ArgumentError, fn -> minimize(["acdc::1", "acdc::gggg"]) end
    assert_raise ArgumentError, fn -> minimize(["1.1.1.1", "acdc::gggg"]) end
    assert_raise ArgumentError, fn -> minimize("1.1.1.0/24") end

    assert [] == minimize([])
    assert ["1.1.1.0/31"] == minimize(["1.1.1.1", "1.1.1.0"])
    assert ["1.1.1.0/31"] == minimize(["1.1.1.1", "1.1.1.0", "1.1.1.1", "1.1.1.0"])
    assert ["1.1.0.0/16"] = minimize(["1.1.0.0/17", "1.1.128.0/17"])

    # output reflects format of first prefix
    assert [{{1, 2, 3, 0}, 24}] == minimize([{1, 2, 3, 0}, "1.2.3.0/25", "1.2.3.128/25"])

    # with partitioning
    assert ["1.1.1.0/24"] == partition("1.1.1.0/24", 25) |> minimize()
    assert ["1.1.1.0/24"] == partition("1.1.1.0/24", 26) |> minimize()
    assert ["1.1.1.0/24"] == partition("1.1.1.0/24", 27) |> minimize()
    assert ["1.1.1.0/24"] == partition("1.1.1.0/24", 28) |> minimize()
    assert ["1.1.1.0/24"] == partition("1.1.1.0/24", 29) |> minimize()
    assert ["1.1.1.0/24"] == partition("1.1.1.0/24", 30) |> minimize()
    assert ["1.1.1.0/24"] == partition("1.1.1.0/24", 31) |> minimize()
    assert ["1.1.1.0/24"] == partition("1.1.1.0/24", 32) |> minimize()

    acl = ["0.0.0.0/8", "255.255.255.255", "0.0.0.0", "240.0.0.0/4"]
    min = minimize(acl)
    assert Enum.sort(["0.0.0.0/8", "240.0.0.0/4"]) == Enum.sort(min)

    acl = ["1.1.1.0/25", "1.1.1.128/26", "1.1.1.192/26"]
    assert ["1.1.1.0/24"] == minimize(acl)
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

    # nth must be an integer
    assert_raise ArgumentError, fn -> member("1.1.1.0/31", 1.0) end
  end

  @tag tst: "member3"
  test "member/3" do
    assert "1.1.1.0/26" == member("1.1.1.0/24", 0, 2)
    assert "1.1.1.64/26" == member("1.1.1.0/24", 1, 2)
    assert "1.1.1.128/26" == member("1.1.1.0/24", 2, 2)
    assert "1.1.1.192/26" == member("1.1.1.0/24", 3, 2)

    # negative nth works too
    assert "1.1.1.0/26" == member("1.1.1.0/24", -4, 2)
    assert "1.1.1.64/26" == member("1.1.1.0/24", -3, 2)
    assert "1.1.1.128/26" == member("1.1.1.0/24", -2, 2)
    assert "1.1.1.192/26" == member("1.1.1.0/24", -1, 2)

    # nth must be an integer
    assert_raise ArgumentError, fn -> member(new("1.1.1.0/24"), 0.0, 2) end
    assert_raise ArgumentError, fn -> member(new("1.1.1.0/24"), 0, 2.0) end
    assert_raise ArgumentError, fn -> member(new("1.1.1.0/24"), 0, -2) end
    assert_raise ArgumentError, fn -> member("1.1.1.0/24", 0, -2) end
    assert_raise ArgumentError, fn -> member("1.1.1.0/44", 1, 2) end
    assert_raise ArgumentError, fn -> member("1.1.1.300/24", 1, 2) end

    # width must be in range
    assert "1.1.1.0" == member("1.1.1.0/30", 0, 2)
    assert_raise ArgumentError, fn -> member("1.1.1.0/30", 0, 3) end
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
             multicast_prefix: "ff70::/12",
             protocol: :ipv6,
             rfc: %{
               group_id: 15,
               unicast_prefix: "2001:db8:beef:feed::/64",
               plen: 64,
               reserved: 0,
               rfc: 3956,
               riid: 3,
               rp_prefix: "2001:db8:beef:feed::3"
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
             multicast_address: "ff31:30:3ffe:ffff:1::8",
             multicast_prefix: "ff30::/12",
             protocol: :ipv6,
             rfc: %{
               group_id: 8,
               unicast_prefix: "3ffe:ffff:1::/48",
               plen: 48,
               reserved: 0,
               rfc: 3306
             },
             scope: 1
           }

    assert multicast_decode("ff00::") == %{
             flags: {0, 0, 0, 0},
             multicast_address: "ff00::",
             multicast_prefix: "ff00::/12",
             protocol: :ipv6,
             rfc: %{group_id: 0, rfc: 4291},
             scope: 0
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

    # pfx6 should be a full IPv6 address
    assert_raise ArgumentError, fn -> nat64_decode("acdc::/32") end

    # len should be in [96, 64, 56, 48, 40, 32]
    assert_raise ArgumentError, fn -> nat64_decode("acdc::", 65) end
    assert nat64_decode("acdc::", 64) != nil
  end

  test "nat64_encode/2" do
    Enum.all?(@ip4_representations, fn x ->
      assert_raise ArgumentError, fn -> nat64_encode(x, x) end
    end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> nat64_encode(x, x) end
    end)

    # pfx4 must be an IPv4 address
    assert_raise ArgumentError, fn -> nat64_encode("acdc::/32", "acdc::") end

    # pfx6 must have specific length
    assert_raise ArgumentError, fn -> nat64_encode("acdc::", "1.1.1.1") end
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
    assert "acdc:1976::" == network("acdc:1976::/32")
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
    # good pfx, bad maxlen
    assert_raise ArgumentError, fn -> new("1.1.1.1") |> new(-1) end
    # good address, bad mask
    assert_raise ArgumentError, fn -> new("1.1.1.1/0024") end

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
    assert 65_536 == partition("acdc::1976/112", 128) |> length()
  end

  test "partition_range/2 with start,nhosts" do
    # start, nhosts
    range = fn x -> partition_range(x, 1) end
    Enum.all?(@ip4_representations, range)
    Enum.all?(@ip6_representations, range)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> range.(x) end end)

    # zero hosts
    assert [] == partition_range("10.10.10.0", 0)
    # some hosts
    assert ["10.10.10.0"] == partition_range("10.10.10.0", 1)
    assert ["10.10.10.0/24"] == partition_range("10.10.10.0", 256)
    # all hosts
    assert ["0.0.0.0/0"] == partition_range("0.0.0.0", trunc(:math.pow(2, 32)))
    # wraps around
    assert ["255.255.255.255", "0.0.0.0/24"] = partition_range("255.255.255.255", 257)
    assert ["255.255.255.255", "0.0.0.0/24"] = partition_range("0.0.0.255", -257)
    # wraps around but starts at `start`
    assert ["255.255.255.255", "0.0.0.0"] == partition_range("255.255.255.255", "0.0.0.0")

    assert_raise ArgumentError, fn -> partition_range("0.0.0.0", 1 + trunc(:math.pow(2, 32))) end
  end

  test "partition_range/2 with start,stop" do
    range = fn x -> partition_range(x, x) end
    Enum.all?(@ip4_representations, range)
    Enum.all?(@ip6_representations, range)
    Enum.all?(@bad_representations, fn x -> assert_raise ArgumentError, fn -> range.(x) end end)

    # prefixes must be comparable
    assert_raise ArgumentError, fn -> partition_range("1.1.1.1", "2001::") end
    assert_raise ArgumentError, fn -> partition_range("2001::", "1.1.1.1") end

    # range of 1
    assert ["10.10.10.10"] == partition_range("10.10.10.10", "10.10.10.10")
    # range of many
    assert ["10.10.10.0/23"] == partition_range("10.10.10.0", "10.10.11.255")
    # wraps address space
    assert ["255.255.255.0/24", "0.0.0.0"] == partition_range("255.255.255.0", "0.0.0.0")

    # normal ranges
    assert ["10.10.0.0/16"] == partition_range("10.10.0.0", "10.10.255.255")
    assert ["0.0.0.0/0"] == partition_range("0.0.0.0", "255.255.255.255")

    assert ["::/0"] ==
             partition_range("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
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
    assert_raise ArgumentError, fn -> remove(new("1.1.1.1"), -64, 8) end

    # position and length must be integers
    assert "2.3.0.0/16" == remove("1.2.3.0/24", 0, 8)
    assert_raise ArgumentError, fn -> remove("1.2.3.0/24", 0.0, 8) end
    assert_raise ArgumentError, fn -> remove("1.2.3.0/24", 0, 8.0) end

    # remove 0 bits
    assert "1.2.3.0/24" == remove("1.2.3.0/24", 0, 0)
    assert "1.2.3.0/24" == remove("1.2.3.0/24", 8, 0)

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

    # nth must be an integer
    assert "1.1.1.1" == sibling("1.1.1.1", 0)
    assert_raise ArgumentError, fn -> sibling("1.1.1.1", 0.0) end

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

  test "sigil_p/2" do
    for d <- 0..255 do
      assert ~p(1.1.#{d}.#{d}) == Pfx.new("1.1.#{d}.#{d}")
    end

    # address
    assert ~p"1.1.1.1/24"a == address("1.1.1.1/24") |> new()
    assert ~p"1.1.1.1/24"aS == "1.1.1.1"
    assert ~p"1.1.1.1/24"aT == {1, 1, 1, 1}

    # mask
    assert ~p"192.168.1.9/23"m == new("255.255.254.0")
    assert ~p"192.168.1.9/23"mS == "255.255.254.0"
    assert ~p"192.168.1.9/23"mT == {255, 255, 254, 0}
    assert ~p"192.168.1.9/23"mT == to_tuple("255.255.254.0", mask: false)

    # first
    assert ~p"1.1.1.134/24"f == new("1.1.1.0")
    assert ~p"1.1.1.134/24"fS == "1.1.1.0"
    assert ~p"1.1.1.134/24"fT == {1, 1, 1, 0}

    # last
    assert ~p"1.1.1.134/24"l == new("1.1.1.255")
    assert ~p"1.1.1.134/24"lS == "1.1.1.255"
    assert ~p"1.1.1.134/24"lT == {1, 1, 1, 255}

    # neighbor
    assert ~p"1.1.1.1"n == new("1.1.1.0")
    assert ~p"1.1.1.0"nS == "1.1.1.1"
    assert ~p"1.1.1.0"nT == {{1, 1, 1, 1}, 32}

    # parent
    assert ~p"1.1.1.1"p == new("1.1.1.0/31")
    assert ~p"1.1.1.1"pS == "1.1.1.0/31"
    assert ~p"1.1.1.1"pT == {{1, 1, 1, 0}, 31}
  end

  test "sigil_p/3" do
    # must be comparable
    assert_raise ArgumentError, fn -> "1.1.1.1" |> ~p(acdc::1) end
    assert_raise ArgumentError, fn -> [1, 1, 1, 1] |> ~p()a end

    # wraps sigil_p
    pfx = "1.1.1.1/24"
    assert pfx |> ~p() == ~p(#{pfx})

    assert pfx |> ~p()a == ~p(#{pfx})a
    assert pfx |> ~p()f == ~p(#{pfx})f
    assert pfx |> ~p()l == ~p(#{pfx})l
    assert pfx |> ~p()n == ~p(#{pfx})n
    assert pfx |> ~p()p == ~p(#{pfx})p

    assert pfx |> ~p()aS == ~p(#{pfx})aS
    assert pfx |> ~p()fS == ~p(#{pfx})fS
    assert pfx |> ~p()lS == ~p(#{pfx})lS
    assert pfx |> ~p()nS == ~p(#{pfx})nS
    assert pfx |> ~p()pS == ~p(#{pfx})pS

    assert pfx |> ~p()aT == ~p(#{pfx})aT
    assert pfx |> ~p()fT == ~p(#{pfx})fT
    assert pfx |> ~p()lT == ~p(#{pfx})lT
    assert pfx |> ~p()nT == ~p(#{pfx})nT
    assert pfx |> ~p()pT == ~p(#{pfx})pT

    # allows all prefix representations
    assert {{1, 1, 1, 1}, 24} |> ~p() == ~p(1.1.1.1/24)
    assert new("1.1.1.1/24") |> ~p() == ~p(1.1.1.1/24)
    assert {1, 1, 1, 1} |> ~p() == ~p(1.1.1.1)
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
    assert 65_536 == size(%Pfx{bits: <<1, 2>>, maxlen: 32})

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

  test "teredo_encode/4" do
    flags = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    # port must be an int
    assert_raise ArgumentError, fn -> teredo_encode("1.1.1.1", "2.2.2.2", "53", flags) end
    # flags must be 16-element tuple
    assert_raise ArgumentError, fn -> teredo_encode("1.1.1.1", "2.2.2.2", 53, {1, 1, 0}) end
    # client/server must be full IPv4 addresses
    assert_raise ArgumentError, fn -> teredo_encode("1.1.1.0/24", "2.2.2.2", 53, flags) end
    assert_raise ArgumentError, fn -> teredo_encode("1.1.1.1", "2.2.2.0/24", 53, flags) end
    # client/server must be parseable for new/1
    assert_raise ArgumentError, fn -> teredo_encode('1.1.1.1', "2.2.2.2", 53, flags) end
    assert_raise ArgumentError, fn -> teredo_encode("1.1.1.1", '2.2.2.2', 53, flags) end
  end

  test "teredo_decode/1" do
    Enum.all?(@ip4_representations, fn x -> assert nil == teredo_decode(x) end)
    Enum.all?(@ip6_representations, fn x -> assert nil == teredo_decode(x) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> teredo_decode(x) end
    end)

    server = new("1.2.3.4")
    client = new("10.10.10.10") |> bnot()
    port = Bitwise.bnot(33_000)
    flags = <<1::1, 0::15>>

    addr = %Pfx{
      bits: <<0x2001::16, 0x0::16, server.bits::bits, flags::bits, port::16, client.bits::bits>>,
      maxlen: 128
    }

    map = teredo_decode(addr)
    assert map.server == %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}
    assert map.client == %Pfx{bits: <<10, 10, 10, 10>>, maxlen: 32}
    assert map.port == 33_000
    assert map.flags == {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    assert map.prefix == addr

    # follows representation of addr for client/server
    map = teredo_decode("#{addr}")
    assert map.server == "1.2.3.4"
    assert map.client == "10.10.10.10"
    assert map.port == 33_000
    assert map.flags == {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    assert map.prefix == "#{addr}"

    # follows representation of addr for client/server
    map = teredo_decode(digits(addr, 16))
    assert map.server == {{1, 2, 3, 4}, 32}
    assert map.client == {{10, 10, 10, 10}, 32}
    assert map.port == 33_000
    assert map.flags == {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    assert map.prefix == digits(addr, 16)
  end

  test "to_tuple/2" do
    Enum.all?(@ip4_representations, fn x -> to_tuple(x) end)
    Enum.all?(@ip6_representations, fn x -> to_tuple(x) end)

    Enum.all?(@bad_representations, fn x ->
      assert_raise ArgumentError, fn -> to_tuple(x) end
    end)

    assert {{0, 0, 0, 0}, 32} == to_tuple("0.0.0.0")
    assert {{0, 0, 0, 0}, 32} == to_tuple({0, 0, 0, 0})
    assert {{0, 0, 0, 0}, 32} == to_tuple(%Pfx{bits: <<0, 0, 0, 0>>, maxlen: 32})

    assert {{128, 128, 128, 128}, 32} == to_tuple("128.128.128.128")
    assert {{128, 128, 128, 128}, 32} == to_tuple({128, 128, 128, 128})
    assert {{128, 128, 128, 128}, 32} == to_tuple(%Pfx{bits: <<128, 128, 128, 128>>, maxlen: 32})

    assert {{255, 255, 255, 255}, 32} == to_tuple("255.255.255.255")
    assert {{255, 255, 255, 255}, 32} == to_tuple({255, 255, 255, 255})
    assert {{255, 255, 255, 255}, 32} == to_tuple(%Pfx{bits: <<255, 255, 255, 255>>, maxlen: 32})

    assert {{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 32} == to_tuple("acdc:1976::/32")

    assert {{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 32} ==
             to_tuple(%Pfx{bits: <<0xACDC::size(16), 0x1976::size(16)>>, maxlen: 128})

    assert {{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 32} ==
             to_tuple({{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 32})
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

  test "type/1" do
    Enum.all?(@ip4_representations, fn x -> assert type(x) == :ip4 end)
    Enum.all?(@ip6_representations, fn x -> assert type(x) == :ip6 end)
    Enum.all?(@bad_representations, fn x -> assert type(x) == :einvalid end)
    # note: cannot test against @eui_representations nor @bad_euis since some
    # of those are interpreted as valid ipv6 prefixes.

    assert :ip4 == type("1.1.1.1")
    assert :ip4 == type({1, 2, 3, 4})
    assert :ip4 == type({{1, 2, 3, 4}, 0})
    assert :ip4 == type(%Pfx{bits: <<>>, maxlen: 32})

    assert :ip6 == type("acdc:1976::1")
    assert :ip6 == type({1, 2, 3, 4, 5, 6, 7, 8})
    assert :ip6 == type({{1, 2, 3, 4, 5, 6, 7, 8}, 0})
    assert :ip6 == type(%Pfx{bits: <<>>, maxlen: 128})

    assert :eui48 == type("11-22-33-44-55-66")
    assert :eui48 == from_mac("11:22:33:44:55:66") |> type()
    assert :eui48 == type(%Pfx{bits: <<>>, maxlen: 48})

    assert :eui64 == type("11-22-33-44-55-66-77-88")
    assert :eui64 == type(%Pfx{bits: <<>>, maxlen: 64})

    # otherwise type reverts to prefix's maxlen property
    assert 65 == type(%Pfx{bits: <<>>, maxlen: 65})
  end

  test "undigits/2" do
    # bad input
    assert_raise ArgumentError, fn -> undigits("1.1.1.1", 8) end
    assert_raise ArgumentError, fn -> undigits({1, 1, 1, 1}, 8) end
    assert_raise ArgumentError, fn -> undigits({{1, 1, 1, 1}, 32}, 1.0) end
    assert_raise ArgumentError, fn -> undigits({{1, 1, 1, 1}, 32}, 0) end
    assert_raise ArgumentError, fn -> undigits({{1, 1.0, 1, 1}, 32}, 8) end
    assert_raise ArgumentError, fn -> undigits({{1, 1, 1, 1}, -32}, 1) end

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

    assert "acdc:1976::" ==
             "#{%Pfx{bits: <<0xACDC::16, 0x1976::16, 0::96>>, maxlen: 128}}"

    assert "acdc:1976:ffff:ffff:ffff:ffff:ffff:ffff" ==
             "#{%Pfx{bits: <<0xACDC::16, 0x1976::16, -1::96>>, maxlen: 128}}"
  end

  test "Enumerable.Pfx" do
    assert 256 == Pfx.new("1.1.1.0/24") |> Enum.count()
    assert 256 == Pfx.new("acdc::/120") |> Enum.count()

    # membership
    assert true == Enum.member?(new("1.1.1.0/24"), new("1.1.1.1"))
    assert false == Enum.member?(new("1.1.1.0/24"), "1.1.1.1")
    assert false == Enum.member?(new("1.1.1.0/24"), new("1.1.0.0/23"))
    assert true == Enum.member?(new("1.1.1.0/23"), new("1.1.0.0/24"))

    # mapping
    assert Enum.map(new("1.1.1.0/30"), fn x -> x end) == [
             %Pfx{bits: <<1, 1, 1, 0>>, maxlen: 32},
             %Pfx{bits: <<1, 1, 1, 1>>, maxlen: 32},
             %Pfx{bits: <<1, 1, 1, 2>>, maxlen: 32},
             %Pfx{bits: <<1, 1, 1, 3>>, maxlen: 32}
           ]

    # take
    assert Enum.take(new("1.1.1.0/30"), 2) == [
             %Pfx{bits: <<1, 1, 1, 0>>, maxlen: 32},
             %Pfx{bits: <<1, 1, 1, 1>>, maxlen: 32}
           ]

    assert Enum.take(new("1.1.1.0/30"), -2) == [
             %Pfx{bits: <<1, 1, 1, 2>>, maxlen: 32},
             %Pfx{bits: <<1, 1, 1, 3>>, maxlen: 32}
           ]

    # reduce
    assert Enum.zip(Pfx.new("1.1.1.0/30"), Pfx.new("2.2.2.0/30")) == [
             {%Pfx{bits: <<1, 1, 1, 0>>, maxlen: 32}, %Pfx{bits: <<2, 2, 2, 0>>, maxlen: 32}},
             {%Pfx{bits: <<1, 1, 1, 1>>, maxlen: 32}, %Pfx{bits: <<2, 2, 2, 1>>, maxlen: 32}},
             {%Pfx{bits: <<1, 1, 1, 2>>, maxlen: 32}, %Pfx{bits: <<2, 2, 2, 2>>, maxlen: 32}},
             {%Pfx{bits: <<1, 1, 1, 3>>, maxlen: 32}, %Pfx{bits: <<2, 2, 2, 3>>, maxlen: 32}}
           ]

    assert Enum.zip(Pfx.new("1.1.1.0/30"), Pfx.new("acdc::")) == [
             {%Pfx{bits: <<1, 1, 1, 0>>, maxlen: 32},
              %Pfx{
                bits: <<172, 220, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
                maxlen: 128
              }}
           ]
  end
end
