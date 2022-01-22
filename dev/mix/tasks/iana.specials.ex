defmodule Mix.Tasks.Iana.Specials do
  use Mix.Task
  alias Mix

  @moduledoc """
  Download and convert IANA's IPv4/6 Special-Purpose Address Registries

  Usage:

  ```
  mix iana.specials [force] [dryrun]
  ```

  The `force` will force the download, even though the xml files are already
  present in the `priv` subdir.

  The `dryrun` will read and convert the downloaded xml files, convert them
  to a map and show the map without writing to disk.

  After download, the xml files are:
  - parsed into a list [{Pfx.t, %{property: value}] per registry
  - sorted more to less specific
  - list are then combined in a map %{ip4: [..], ip6: [..]}
  - that map is then saved as `priv/specials` in erlang external term format

  Pfx uses that file as an external resource for a module attribute that allows
  looking up IANA attributes for a given prefix via `Pfx.iana_special/2`.

  """

  @shortdoc "Takes a snapshot of IANA's IPv4/6 Special-Purpose Address Registries"

  import SweetXml

  @iana_url "http://www.iana.org/assignments"
  @iana_ip4_spar "#{@iana_url}/iana-ipv4-special-registry/iana-ipv4-special-registry.xml"
  @iana_ip6_spar "#{@iana_url}/iana-ipv6-special-registry/iana-ipv6-special-registry.xml"
  @priv_ip4_spar "priv/iana-ipv4-special-registry.xml"
  @priv_ip6_spar "priv/iana-ipv6-special-registry.xml"
  @priv_specials "priv/specials"
  @user_agent {'User-agent', 'Elixir Pfx'}

  @impl Mix.Task
  def run(args) do
    force = "force" in args
    dryrun = "dryrun" in args

    if force or not File.exists?(@priv_ip4_spar),
      do: fetch(@iana_ip4_spar, @priv_ip4_spar),
      else: IO.puts("#{@priv_ip4_spar} exists, skipping download")

    if force or not File.exists?(@priv_ip6_spar),
      do: fetch(@iana_ip6_spar, @priv_ip6_spar),
      else: IO.puts("#{@priv_ip6_spar} exists, skipping download")

    map = %{
      ip4: xml2list(@priv_ip4_spar),
      ip6: xml2list(@priv_ip6_spar)
    }

    if dryrun do
      Mix.shell().info("IANA IPv4 Special-Purpose Address Registry")
      IO.inspect(map.ip4)
      Mix.shell().info("\nIANA IPv6 Special-Purpose Address Registry")
      IO.inspect(map.ip6)
    else
      map
      |> :erlang.term_to_binary()
      |> save_term(@priv_specials)
    end

    Mix.shell().info("Done.")
  end

  defp fetch(url, priv) do
    with {:ok, {{_http_ver, 200, 'OK'}, _headers, body}} <-
           :httpc.request(:get, {url, [@user_agent]}, [], []) do
      # filter out a line, since xmerl chokes on it.
      body =
        List.to_string(body)
        |> String.split("\n")
        |> Enum.map(&String.trim/1)
        |> Enum.filter(fn line -> not String.starts_with?(line, "<?xml-model href") end)
        |> Enum.join("\n")

      File.write!(priv, body)
      IO.puts("donwloaded #{url} -> #{priv} (#{String.length(body)} bytes)")
    else
      metadata ->
        IO.puts("Error: #{url}")
        IO.puts("#{inspect(metadata)}")
    end
  end

  defp save_term(term, path),
    do: File.write!(path, term)

  defp xml2list(file) do
    # note: sort list on prefix: more to less specific
    {:ok, xml} = File.read(file)

    records =
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

    IO.puts("extract: #{file} -> #{length(records)} records")
    records
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
    for pfx <- pfxs, do: {Pfx.new(pfx), Map.put(elm, :prefix, pfx)}
  end

  defp to_stringp(str) do
    keep = Enum.to_list(?a..?z) ++ Enum.to_list(?0..?9) ++ [?\s, ?-, ?/]

    str
    |> to_string()
    |> String.downcase()
    |> String.to_charlist()
    |> Enum.filter(fn c -> c in keep end)
    |> List.to_string()
    |> String.replace(~r/\s+/, "-")
  end

  defp to_prefixp(str) do
    str
    |> String.split(",")
    |> Enum.map(&String.trim/1)
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
