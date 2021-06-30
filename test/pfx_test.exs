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

  test "is_pfx/1 guard detects valid %Pfx{}'s" do
    assert is_pfx(%Pfx{bits: <<>>, maxlen: 0})
  end

  test "is_pfx/1 detects invalid Pfx structs" do
    # maxlen not non_neg_integer
    refute is_pfx(%Pfx{bits: <<>>, maxlen: -1})
    refute is_pfx(%Pfx{bits: <<>>, maxlen: 0.0})

    # more bits than maxlen allows
    refute is_pfx(%Pfx{bits: <<255>>, maxlen: 7})

    # bits not a bitstring
    refute is_pfx(%Pfx{bits: 42, maxlen: 0})
    refute is_pfx(%Pfx{bits: '11', maxlen: 0})
  end

  test "is_pfx/1 detects its arg is not a Pfx struct" do
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
  end

  test "new/1, new/2 return a %Pfx{}" do
    null = %Pfx{bits: <<>>, maxlen: 0}

    assert null == new(null)
    assert null == new(<<>>, 0)
    # binary is also a bitstring
    assert null == new("", 0)
  end

  test "new/1, new/2 understand ip4/6 representations" do
    Enum.all?(@ip4_representations, fn pfx -> assert new(pfx) end)
    Enum.all?(@ip6_representations, fn pfx -> assert new(pfx) end)
  end

  test "new/1, new/2 produce correct %Pfx{} for ip4" do
    addr = %Pfx{bits: <<1, 2, 3, 4>>, maxlen: 32}
    netw = %Pfx{bits: <<1, 2, 3>>, maxlen: 32}

    assert addr == new(addr)
    assert addr == new("1.2.3.4")
    assert addr == new("1.2.3.4/32")
    assert addr == new({1, 2, 3, 4})
    assert addr == new({{1, 2, 3, 4}, 32})
    assert addr == new({{1, 2, 3, 4}, nil})

    assert netw == new(netw)
    assert netw == new("1.2.3.0/24")
    assert netw == new("1.2.3.4/24")
    assert netw == new({{1, 2, 3, 0}, 24})
    assert netw == new({{1, 2, 3, 4}, 24})
  end

  test "new/1, new/2 produce correct %Pfx{} for ip6" do
    addr = %Pfx{bits: <<0xACDC::16, 0x1976::16, 0::96>>, maxlen: 128}
    netw = %Pfx{bits: <<0xACDC::16, 0x1976::16>>, maxlen: 128}

    assert addr == new(addr)
    assert addr == new(<<0xAC, 0xDC, 0x19, 0x76, 0::96>>, 128)
    assert addr == new("acdc:1976::")
    assert addr == new({0xACDC, 0x1976, 0, 0, 0, 0, 0, 0})
    assert addr == new({{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 128})
    # nil means no mask supplied, default to full mask
    assert addr == new({{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, nil})

    assert netw == new(netw)
    assert netw == new(<<0xACDC::16, 0x1976::16>>, 128)
    assert netw == new("acdc:1976::/32")
    assert netw == new({{0xACDC, 0x1976, 0, 0, 0, 0, 0, 0}, 32})
  end

  test "new/1, new/2 apply mask when creating a prefix" do
    network = %Pfx{bits: <<1, 2, 3>>, maxlen: 32}

    assert network == new("1.2.3.255/24")
    assert network == new({{1, 2, 3, 255}, 24})
  end

  test "new/1 raises ArgumentError for invalid input" do
    f = fn x -> assert_raise ArgumentError, fn -> new(x) end end
    Enum.all?(@bad_representations, f)
  end

  test "new/2 raises ArgumentError for invalid input" do
    assert_raise ArgumentError, fn -> new(<<>>, -1) end
    assert_raise ArgumentError, fn -> new([], 0) end
    assert_raise ArgumentError, fn -> new('', 0) end
    assert_raise ArgumentError, fn -> new(%Pfx{bits: <<>>, maxlen: 0}, -1) end
  end

  # Bit Ops

  test "cut/3 cuts bits into their own prefix" do
    bits = %Pfx{bits: <<255, 0>>, maxlen: 16}

    assert %Pfx{bits: <<>>, maxlen: 0} == cut(bits, 0, 0)
    assert %Pfx{bits: <<>>, maxlen: 0} == cut(bits, 15, 0)

    assert %Pfx{bits: <<1::1>>, maxlen: 1} == cut(bits, 0, 1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, 8, 1)
    assert %Pfx{bits: <<255>>, maxlen: 8} = cut(bits, 0, 8)
    assert %Pfx{bits: <<0>>, maxlen: 8} = cut(bits, 8, 8)
    # 0b1111.0000 is 240
    assert %Pfx{bits: <<240>>, maxlen: 8} = cut(bits, 4, 8)
  end

  test "cut/3 cuts both ways" do
    bits = %Pfx{bits: <<255, 0>>, maxlen: 16}

    assert %Pfx{bits: <<1::1>>, maxlen: 1} == cut(bits, 0, -1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, 8, -1)
    assert %Pfx{bits: <<255>>, maxlen: 8} = cut(bits, 7, -8)
    assert %Pfx{bits: <<0>>, maxlen: 8} = cut(bits, 15, -8)
    # 0b1111.0000 is 240
    assert %Pfx{bits: <<240>>, maxlen: 8} = cut(bits, 11, -8)
  end

  test "cut/3 takes perspective" do
    # 1111.1111.0000.0000
    # |       |         |
    # -16     -9        -1
    bits = %Pfx{bits: <<255, 0>>, maxlen: 16}

    assert %Pfx{bits: <<1::1>>, maxlen: 1} == cut(bits, -16, -1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, -1, -1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, -8, -1)
    assert %Pfx{bits: <<255>>, maxlen: 8} == cut(bits, -9, -8)
    assert %Pfx{bits: <<0>>, maxlen: 8} == cut(bits, -1, -8)
    # 0b1111.0000 is 240
    assert %Pfx{bits: <<240>>, maxlen: 8} = cut(bits, -5, -8)

    assert %Pfx{bits: <<1::1>>, maxlen: 1} == cut(bits, -9, 1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, -8, 1)
    assert %Pfx{bits: <<0::1>>, maxlen: 1} == cut(bits, -1, 1)
    assert %Pfx{bits: <<128>>, maxlen: 8} == cut(bits, -9, 8)
    # 0b1111.0000 is 240
    assert %Pfx{bits: <<240>>, maxlen: 8} = cut(bits, -12, 8)
  end

  test "cut/3 raises on invalid input" do
    assert_raise ArgumentError, fn -> cut(%Pfx{bits: <<255>>, maxlen: 7}, 0, 0) end
    assert_raise ArgumentError, fn -> cut(%Pfx{bits: <<255>>, maxlen: 7}, 0, 3) end
    assert_raise ArgumentError, fn -> cut(%Pfx{bits: <<255>>, maxlen: 8}, -1, 3) end
    assert_raise ArgumentError, fn -> cut(%Pfx{bits: <<255>>, maxlen: 8}, 0, 9) end
  end

  test "bit/2 yields bit value for all representations" do
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

  test "bits/3 raises on invalid input" do
    f = fn x -> assert_raise ArgumentError, fn -> cut(x, 0, 0) end end
    Enum.all?(@bad_representations, f)

    # illegal ranges
    assert_raise ArgumentError, fn -> bits(%Pfx{bits: <<255>>, maxlen: 7}, 0, 3) end
    assert_raise ArgumentError, fn -> bits(%Pfx{bits: <<255>>, maxlen: 7}, 0, 3) end
    assert_raise ArgumentError, fn -> bits(%Pfx{bits: <<255>>, maxlen: 8}, -1, 3) end
    assert_raise ArgumentError, fn -> bits(%Pfx{bits: <<255>>, maxlen: 8}, 0, 9) end
  end
end
