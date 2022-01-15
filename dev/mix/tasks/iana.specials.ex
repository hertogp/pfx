defmodule Mix.Tasks.Iana.Specials do
  use Mix.Task
  alias Mix
  import SweetXml

  @user_agent {'User-agent', 'Elixir Pfx'}
  @iana_url "http://www.iana.org/assignments"
  @ip4_iana_spar "#{@iana_url}/iana-ipv4-special-registry/iana-ipv4-special-registry.xml"
  @ip4_priv_spar "priv/iana-ipv4-special-registry.xml"
  @ip6_iana_spar "#{@iana_url}/iana-ipv6-special-registry/iana-ipv6-special-registry.xml"
  @ip6_priv_spar "priv/iana-ipv6-special-registry.xml"
  @pfx_spar "priv/specials"

  @impl Mix.Task
  def run(args) do
    force = "force" in args

    if force or not File.exists?(@ip4_priv_spar),
      do: fetch(@ip4_iana_spar, @ip4_priv_spar),
      else: IO.puts("#{@ip4_priv_spar} exists, skipping download")

    if force or not File.exists?(@ip6_priv_spar),
      do: fetch(@ip6_iana_spar, @ip6_priv_spar),
      else: IO.puts("#{@ip6_priv_spar} exists, skipping download")

    %{
      ip4: xml2list(@ip4_priv_spar),
      ip6: xml2list(@ip6_priv_spar)
    }
    |> IO.inspect(label: :result)
    |> :erlang.term_to_binary()
    |> save_term(@pfx_spar)
  end

  defp fetch(url, priv) do
    with {:ok, {{_http_ver, 200, 'OK'}, _headers, body}} <-
           :httpc.request(:get, {url, [@user_agent]}, [], []) do
      # filter out a line, since xmerl chokes on it.
      body =
        List.to_string(body)
        |> String.split("\n")
        |> Enum.filter(fn line -> not String.starts_with?(line, "<?xml-model href") end)
        |> Enum.join("\n")

      File.write!(priv, body)
      IO.puts("got: #{url}")
      IO.puts(" to: #{priv}")
    else
      metadata ->
        IO.puts("Error: #{url}")
        IO.puts("#{inspect(metadata)}")
    end
  end

  defp save_term(term, path),
    do: File.write!(path, term)

  defp xml2list(file) do
    {:ok, xml} = File.read(file)

    xml
    |> xpath(
      ~x"//record"l,
      prefix: ~x"./address/text()"s,
      name: ~x"./name/text()"s,
      source: ~x"./source/text()"s,
      destination: ~x"./destination/text()"s,
      forward: ~x"./forwardable/text()"s,
      global: ~x"./global/text()"s,
      reserved: ~x"./reserved/text()"s,
      allocation: ~x"./allocation/text()"s,
      spec: ~x"./spec/xref/@data"l
    )
    |> Enum.map(fn elm -> normalize(elm) end)
    |> List.flatten()
    |> Enum.sort(fn x, y -> bit_size(elem(x, 0).bits) >= bit_size(elem(y, 0).bits) end)
  end

  defp normalize(elm) do
    pfxs = Map.get(elm, :prefix) |> to_prefixp()
    elm = Map.delete(elm, :prefix)
    elm = Map.put(elm, :name, to_stringp(elm.name))
    elm = Map.put(elm, :source, to_booleanp(elm.source))
    elm = Map.put(elm, :destination, to_booleanp(elm.destination))
    elm = Map.put(elm, :forward, to_booleanp(elm.forward))
    elm = Map.put(elm, :global, to_booleanp(elm.global))
    elm = Map.put(elm, :reserved, to_booleanp(elm.reserved))
    elm = Map.put(elm, :allocation, to_stringp(elm.allocation))
    elm = Map.put(elm, :spec, Enum.map(elm.spec, fn x -> to_stringp(x) end))
    for pfx <- pfxs, do: {pfx, Map.put(elm, :prefix, "#{pfx}")}
  end

  defp to_stringp(str) do
    str
    |> to_string()
    |> String.downcase()
    |> String.replace(~r/\s+/, "-")
    |> String.replace(~r/^"/, "")
    |> String.replace(~r/"$/, "")
  end

  defp to_prefixp(str) do
    str
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&Pfx.new/1)
  end

  defp to_booleanp(str) do
    str = String.downcase(str)

    cond do
      String.contains?(str, "false") -> false
      String.contains?(str, "true") -> true
      true -> :na
    end
  end
end
