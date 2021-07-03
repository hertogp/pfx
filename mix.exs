defmodule Pfx.MixProject do
  use Mix.Project

  # Before publishing to Hex:
  # - set version tag in mix.exs, README.md
  # - mix test
  # - mix docz
  # - mix dialyzer
  # - git tag -a vx.y.z -m 'Release vx.y.z'
  # - git push --tags
  # mix hex.publish

  @version "0.1.1"
  @url "https://github.com/hertogp/pfx"

  def project do
    [
      app: :pfx,
      version: @version,
      elixir: "~> 1.11",
      name: "Pfx",
      description: "Functions to work with (IPv4/IPv6/Other) prefixes.",
      deps: deps(),
      docs: docs(),
      package: package(),
      aliases: aliases()
    ]
  end

  def application do
    []
  end

  defp docs() do
    [
      main: Pfx,
      extras: ["README.md", "CHANGELOG.md"],
      source_url: @url,
      groups_for_functions: [
        "IP Functions": &(&1[:section] == :ip),
        Guards: &(&1[:section] == :guard)
      ]
    ]
  end

  defp package do
    %{
      licenses: ["MIT"],
      maintainers: ["hertogp"],
      links: %{"GitHub" => @url}
    }
  end

  defp aliases() do
    [docz: ["docs", &cp_images/1]]
  end

  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: :dev, runtime: false},
      {:benchee, "~> 1.0", only: :dev}
    ]
  end

  defp cp_images(_) do
    # On hex.pm, image links are taken to be relative to the repo's
    # root/doc directory.  Hence, the img/*.dot files are processed into
    # img/*.png files, after which the img/*.png files are copied to
    # doc/img/*.png so everybody is happy.

    # ensure the (untracked) doc/img directory for hex.pm
    Path.join("doc", "img")
    |> File.mkdir_p!()

    # process all img/*.dot files into img/*.dot.png image files
    Path.wildcard("img/*.dot")
    |> Enum.map(fn file -> System.cmd("dot", ["-O", "-Tpng", file]) end)

    # copy img/*.png to doc/img/*.png
    Path.wildcard("img/*.png")
    |> Enum.map(fn src -> {src, Path.join("doc", src)} end)
    |> Enum.map(fn {src, dst} -> File.cp!(src, dst) end)
  end
end
