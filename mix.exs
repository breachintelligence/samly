defmodule Samly.Mixfile do
  use Mix.Project

  @version "1.4.0"
  @description "SAML Single-Sign-On Authentication for Plug/Phoenix Applications"
  @source_url "https://github.com/dropbox/samly"

  def project() do
    [
      app: :samly,
      version: @version,
      description: @description,
      docs: docs(),
      package: package(),
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application() do
    [
      extra_applications: [:logger, :eex]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps() do
    [
      {:plug, "~> 1.6"},
      {:sweet_xml, "~> 0.6"},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:esaml, git: "https://github.com/breachintelligence/esaml.git"}
    ]
  end

  defp docs() do
    [
      extras: ["README.md"],
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end

  defp package() do
    [
      maintainers: ["dropbox", "KMC"],
      files: ["config", "lib", "LICENSE", "mix.exs", "README.md"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end
end
