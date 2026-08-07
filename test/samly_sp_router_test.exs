defmodule SamlySpRouterTest do
  use ExUnit.Case, async: false
  use Plug.Test

  alias Samly.{IdpData, SPRouter, SpData}

  @router_opts SPRouter.init([])
  @sp_config %{
    id: "sp1",
    entity_id: "urn:test:sp1",
    certfile: "test/data/test.crt",
    keyfile: "test/data/test.pem"
  }
  @idp_config %{
    id: "idp1",
    sp_id: "sp1",
    base_url: "http://samly.howto:4003/sso",
    metadata_file: "test/data/idp_metadata.xml"
  }

  setup do
    original_idp_id_from = Application.get_env(:samly, :idp_id_from)
    original_idps = Application.get_env(:samly, :identity_providers)

    sp = SpData.load_provider(@sp_config)
    idp = IdpData.load_provider(@idp_config, %{"sp1" => sp})

    Application.put_env(:samly, :idp_id_from, :path_segment)
    Application.put_env(:samly, :identity_providers, %{"idp1" => idp})

    on_exit(fn ->
      restore_env(:idp_id_from, original_idp_id_from)
      restore_env(:identity_providers, original_idps)
    end)

    :ok
  end

  test "accepts a LogoutResponse using the HTTP-Redirect binding" do
    relay_state = "relay-state"
    response = logout_response()

    redirect_url =
      :esaml_binding.encode_http_redirect(
        ~c"/logout/idp1",
        response,
        :undefined,
        relay_state
      )

    :get
    |> conn(redirect_url)
    |> assert_signed_out(relay_state)
  end

  test "accepts a LogoutResponse using the HTTP-POST binding" do
    relay_state = "relay-state"

    saml_response =
      [logout_response()]
      |> :xmerl.export(:xmerl_xml)
      |> IO.iodata_to_binary()
      |> Base.encode64()

    :post
    |> conn("/logout/idp1", %{
      "SAMLResponse" => saml_response,
      "RelayState" => relay_state
    })
    |> assert_signed_out(relay_state)
  end

  test "rejects a LogoutRequest using the HTTP-Redirect binding" do
    conn =
      :get
      |> conn("/logout/idp1?SAMLRequest=request")
      |> init_test_session(%{})
      |> SPRouter.call(@router_opts)

    assert conn.status == 403
    assert conn.resp_body == "invalid_request"
  end

  defp restore_env(key, nil), do: Application.delete_env(:samly, key)
  defp restore_env(key, value), do: Application.put_env(:samly, key, value)

  defp assert_signed_out(conn, relay_state) do
    conn =
      conn
      |> init_test_session(%{
        "relay_state" => relay_state,
        "idp_id" => "idp1",
        "target_url" => "/signed-out"
      })
      |> SPRouter.call(@router_opts)

    assert conn.status == 302, conn.resp_body
    assert get_resp_header(conn, "location") == ["/signed-out"]
  end

  defp logout_response do
    xml = ~c"""
    <samlp:LogoutResponse
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      IssueInstant="2026-08-07T12:00:00Z"
      Destination="http://samly.howto:4003/sso/sp/logout/idp1">
      <saml:Issuer>https://idp.example.com</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
    </samlp:LogoutResponse>
    """

    {response, _} = :xmerl_scan.string(xml, namespace_conformant: true)
    response
  end
end
