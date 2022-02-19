defmodule Mix.Tasks.Iana.SpecialsTest do
  use ExUnit.Case

  @specials_file "priv/specials"

  setup do
    Mix.shell(Mix.Shell.Process)
    on_exit(fn -> Mix.shell(Mix.Shell.IO) end)
  end

  test "run/1" do
    # ensure we will update the specials file
    File.touch(@specials_file, {{1970, 1, 1}, {0, 0, 0}})
    Mix.Tasks.Iana.Specials.run([])
    assert_received {:mix_shell, :info, [line1]}
    assert_received {:mix_shell, :info, [line2]}
    assert_received {:mix_shell, :info, [line3]}
    assert_received {:mix_shell, :info, [line4]}

    assert String.starts_with?(line1, "IANA IPv4")
    assert String.starts_with?(line2, "IANA IPv6")
    assert String.starts_with?(line3, "Local Pfx")
    assert String.ends_with?(line4, "updated")

    # Repeating the exercise should yield "up-to-date"
    Mix.Tasks.Iana.Specials.run([])
    assert_received {:mix_shell, :info, [line1]}
    assert_received {:mix_shell, :info, [line2]}
    assert_received {:mix_shell, :info, [line3]}
    assert_received {:mix_shell, :info, [line4]}

    assert String.starts_with?(line1, "IANA IPv4")
    assert String.starts_with?(line2, "IANA IPv6")
    assert String.starts_with?(line3, "Local Pfx")
    assert String.ends_with?(line4, "up-to-date")
  end

  test "priv/specials" do
    specials = File.read!("priv/specials") |> :erlang.binary_to_term()

    assert Map.has_key?(specials, :ip4)
    assert Map.has_key?(specials, :ip6)

    assert length(specials.ip4) > 0
    assert length(specials.ip6) > 0

    # Take first element and check its {Pfx.t, map}
    {pfx, props} = hd(specials.ip4)
    assert %Pfx{} = pfx
    assert pfx.maxlen == 32
    assert Map.has_key?(props, :allocation)
    assert Map.has_key?(props, :destination)
    assert Map.has_key?(props, :forward)
    assert Map.has_key?(props, :global)
    assert Map.has_key?(props, :name)
    assert Map.has_key?(props, :prefix)
    assert Map.has_key?(props, :reserved)
    assert Map.has_key?(props, :source)
    assert Map.has_key?(props, :spec)
    assert Map.has_key?(props, :termination)

    {pfx, props} = hd(specials.ip6)
    assert %Pfx{} = pfx
    assert pfx.maxlen == 128
    assert Map.has_key?(props, :allocation)
    assert Map.has_key?(props, :destination)
    assert Map.has_key?(props, :forward)
    assert Map.has_key?(props, :global)
    assert Map.has_key?(props, :name)
    assert Map.has_key?(props, :prefix)
    assert Map.has_key?(props, :reserved)
    assert Map.has_key?(props, :source)
    assert Map.has_key?(props, :spec)
    assert Map.has_key?(props, :termination)
  end
end
