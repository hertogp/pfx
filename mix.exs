defmodule Pfx.MixProject do
  use Mix.Project

  # Before publishing to Hex:
  # - set version tag in mix.exs, README.md & CHANGELOG.md
  # - mix test
  # - mix docs
  # - mix dialyzer
  # - git tag -a vx.y.z -m 'Release vx.y.z'
  # - git push --tags
  # mix hex.publish

  @version "0.12.0"
  @source_url "https://github.com/hertogp/pfx"

  def project do
    [
      app: :pfx,
      version: @version,
      elixir: "~> 1.11",
      name: "Pfx",
      description: "Functions to work with prefixes, especially IP (both IPv4 and IPv6).",
      deps: deps(),
      docs: docs(),
      package: package(),
      aliases: aliases(),
      preferred_cli_env: [ci: :test],
      elixirc_paths: elixirc_paths(Mix.env()),
      dialyzer: [plt_add_apps: [:mix]]
    ]
  end

  def application,
    do: applications(Mix.env())

  # do: [applications: [:inets]]

  def applications(:prod),
    do: []

  def applications(_),
    do: [applications: [:sweet_xml, :inets]]

  defp elixirc_paths(:dev),
    do: ["lib", "dev"]

  defp elixirc_paths(_),
    do: ["lib"]

  defp docs() do
    [
      main: "readme",
      extras: [
        "README.md": [title: "Overview"],
        "LICENSE.md": [title: "License"],
        "CHANGELOG.md": []
      ],
      source_url: @source_url,
      source_ref: "v#{@version}",
      formatters: ["html"],
      groups_for_functions: [
        Guards: &(&1[:section] == :guard),
        "IP Functions": &(&1[:section] == :ip)
      ],
      assets: "assets"
    ]
  end

  defp package do
    %{
      licenses: ["MIT"],
      maintainers: ["hertogp"],
      links: %{
        "Changelog" => "https://hexdocs.pm/pfx/changelog.html",
        "GitHub" => @source_url
      }
    }
  end

  defp aliases() do
    [
      docs: ["docs", &gen_images/1],
      ci: [
        "format --check-formatted",
        "deps.unlock --check-unused",
        "test --cover",
        "dialyzer"
      ]
    ]
  end

  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: :dev, runtime: false},
      {:benchee, "~> 1.0", only: :dev, runtime: false},
      {:sweet_xml, "~> 0.7.1", only: :dev, runtime: false}
    ]
  end

  defp gen_images(_) do
    for dot <- Path.wildcard("assets/*.dot") do
      System.cmd("dot", ["-O", "-Tpng", dot])
    end
  end
end
