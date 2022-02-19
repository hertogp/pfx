defmodule Mix.Tasks.Iana.Specials do
  use Mix.Task
  alias Mix

  @moduledoc """
  Download IANA IPv4/6 Special-Purpose Address Registries and store locally.

  Usage:

  ```
  mix iana.specials
  ```

  The xml registry files are:
  - parsed into a list [{Pfx.t, %{property: value}] per registry
  - each list is sorted more to less specific
  - the lists are then stored in a map %{ip4: [..], ip6: [..]}
  - that map is then saved as `priv/specials` in erlang external term format

  Pfx uses `priv/specials` as an external resource for a module attribute that allows
  looking up IANA attributes for a given prefix via `Pfx.iana_special/2`.

  """

  @shortdoc "Checks IANA IPv4/6 Special-Purpose Address Registries for updates"

  @iana_url "http://www.iana.org/assignments"
  @iana_ip4_spar "#{@iana_url}/iana-ipv4-special-registry/iana-ipv4-special-registry.xml"
  @iana_ip6_spar "#{@iana_url}/iana-ipv6-special-registry/iana-ipv6-special-registry.xml"

  @user_agent {'User-agent', 'Elixir Pfx'}
  @priv_specials "priv/specials"

  # used to normalize strings
  @keep Enum.to_list(?a..?z) ++ Enum.to_list(?0..?9) ++ [?\s, ?-, ?/]

  @impl Mix.Task
  def run(_args) do
    {ip4_updated, ip4} = fetch(@iana_ip4_spar)
    {ip6_updated, ip6} = fetch(@iana_ip6_spar)
    {reg_updated, reg} = read(@priv_specials)
    num_records = length(reg.ip4) + length(reg.ip6)

    Mix.shell().info("IPv4 special registry: #{length(ip4)} records, last update #{ip4_updated}.")
    Mix.shell().info("IPv6 special registry: #{length(ip6)} records, last update #{ip6_updated}.")
    Mix.shell().info("Pfx  special registry: #{num_records} records, last update #{reg_updated}.")

    if Date.compare(ip4_updated, reg_updated) == :gt or
         Date.compare(ip6_updated, reg_updated) == :gt do
      save_term(%{ip4: ip4, ip6: ip6}, @priv_specials)
      Mix.shell().info("\nLocal Pfx special registry updated")
    else
      Mix.shell().info("\nLocal Pfx special registry is up-to-date")
    end
  end

  @spec fetch(String.t()) :: {:error, String.t()} | {Date.t(), [{Pfx.t(), map}]}
  defp fetch(url) do
    # filter out ?xml-model since xmerl chokes on it.
    with {:ok, {{_http_ver, 200, 'OK'}, _headers, body}} <-
           :httpc.request(:get, {url, [@user_agent]}, [], []),
         body <- List.to_string(body),
         body <- Regex.replace(~r/<\?xml-model.*\n/, body, ""),
         body <- to_charlist(body) do
      xml2list(body)
    else
      metadata -> {:error, "#{inspect(metadata)}"}
    end
  end

  @spec read(Path.t()) :: {Date.t(), map}
  defp read(fpath) do
    with true <- File.exists?(fpath),
         {:ok, stat} <- File.stat(fpath),
         true <- stat.size > 0,
         {{y, m, d}, _} <- stat.mtime,
         registry <- File.read!(fpath) |> :erlang.binary_to_term() do
      {Date.new!(y, m, d), registry}
    else
      _ -> {Date.new!(1970, 1, 1), %{ip4: [], ip6: []}}
    end
  end

  @spec save_term(any, Path.t()) :: :ok
  defp save_term(term, path),
    do: File.write!(path, :erlang.term_to_binary(term))

  @spec xml2list(charlist) :: {Date.t(), [{Pfx.t(), map}]}
  defp xml2list(body) do
    {elm, _} = :xmerl_scan.string(body, [{:space, :normalize}])
    [clean] = :xmerl_lib.remove_whitespace([elm])
    simple = :xmerl_lib.simplify_element(clean) |> elem(2)
    {last_modified(simple), records(simple)}
  end

  @spec last_modified([{atom, list, list}]) :: Date.t()
  defp last_modified(simple) do
    {:ok, last} =
      simple
      |> Enum.filter(fn x -> elem(x, 0) == :updated end)
      |> hd()
      |> elem(2)
      |> hd()
      |> List.to_string()
      |> Date.from_iso8601()

    last
  end

  @spec records([{atom, list, list}]) :: [{Pfx.t(), map}]
  defp records(simple) do
    simple
    |> Enum.filter(fn x -> elem(x, 0) == :registry end)
    |> hd()
    |> elem(2)
    |> Enum.filter(fn x -> elem(x, 0) == :record end)
    |> Enum.map(&to_map/1)
    |> Enum.map(&normalize/1)
    |> List.flatten()
    |> Enum.sort(fn x, y -> bit_size(elem(x, 0).bits) >= bit_size(elem(y, 0).bits) end)
  end

  @spec to_map({atom, list, [tuple]}) :: map
  defp to_map(record) do
    elem(record, 2)
    |> Enum.map(&convert/1)
    |> Enum.into(%{})
  end

  @spec convert({atom, list, any}) :: {atom, any}
  defp convert({:address, _, data}) do
    # ignore {:xref,  _, _} if any, we want only the list 'pfx1, pfx2'
    data =
      data
      |> Enum.filter(&is_list/1)
      |> Enum.map(&to_string/1)
      |> Enum.map(fn x -> String.split(x, ",") end)
      |> List.flatten()
      |> Enum.map(&String.trim/1)

    {:address, data}
  end

  defp convert({:spec, _, data}) do
    rfcs =
      for xref <- data do
        case xref do
          {:xref, [type: 'rfc', data: rfc], _} -> to_string(rfc)
          _ -> ""
        end
      end
      |> Enum.map(&String.trim/1)
      |> Enum.filter(fn x -> x != "" end)

    {:spec, rfcs}
  end

  defp convert({field, _, []}),
    do: {field, ""}

  defp convert({field, _, data}) do
    data = Enum.filter(data, &is_list/1) |> hd()
    {field, to_string(data)}
  end

  @spec normalize(map) :: [map]
  defp normalize(rec) do
    rec = Map.put(rec, :name, sanitizep(rec.name))
    rec = Map.put(rec, :allocation, sanitizep(rec.allocation))
    rec = Map.put(rec, :source, to_boolish(rec.source))
    rec = Map.put(rec, :destination, to_boolish(rec.destination))
    rec = Map.put(rec, :global, to_boolish(rec.global))
    rec = Map.put(rec, :reserved, to_boolish(rec.reserved))

    # forwardable := forward
    rec = Map.put(rec, :forward, to_boolish(rec.forwardable))
    rec = Map.delete(rec, :forwardable)

    # ensure termination is always present
    rec = Map.put_new(rec, :termination, :na)

    # address := prefix
    # note: address may contain multiple prefixes
    pfxs = Map.get(rec, :address)
    rec = Map.delete(rec, :address)
    for pfx <- pfxs, do: {Pfx.new(pfx), Map.put(rec, :prefix, pfx)}
  end

  @spec sanitizep(String.t()) :: String.t()
  defp sanitizep(str) do
    # sanitize strings
    str
    |> to_string()
    |> String.downcase()
    |> String.to_charlist()
    |> Enum.filter(fn c -> c in @keep end)
    |> List.to_string()
    |> String.replace(~r/\s+/, "-")
  end

  @spec to_boolish(String.t()) :: true | false | :na
  defp to_boolish(str) do
    str = String.downcase(str)

    cond do
      String.contains?(str, "false") -> false
      String.contains?(str, "true") -> true
      true -> :na
    end
  end
end
