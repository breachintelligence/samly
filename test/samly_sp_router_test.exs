defmodule SamlySpRouterTest do
  use ExUnit.Case, async: false
  use Plug.Test

  require Samly.Esaml
  alias Samly.{Assertion, Esaml, IdpData, SPRouter, SpData, State, Subject}

  @router_opts SPRouter.init([])
  @rsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
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
    original_state_store = Application.get_env(:samly, :state_store)

    sp = SpData.load_provider(@sp_config)
    idp = IdpData.load_provider(@idp_config, %{"sp1" => sp})
    trusted_fingerprints = [{:sha256, :crypto.hash(:sha256, sp.cert)}]

    sp_rec =
      Esaml.esaml_sp(idp.esaml_sp_rec, trusted_fingerprints: trusted_fingerprints)

    idp = %IdpData{idp | esaml_sp_rec: sp_rec, certs: [Base.encode64(sp.cert)]}

    Application.put_env(:samly, :idp_id_from, :path_segment)
    Application.put_env(:samly, :identity_providers, %{"idp1" => idp})
    State.init(State.ETS, table: :samly_sp_router_test_assertions)
    :ets.delete_all_objects(:samly_sp_router_test_assertions)

    on_exit(fn ->
      restore_env(:idp_id_from, original_idp_id_from)
      restore_env(:identity_providers, original_idps)
      restore_env(:state_store, original_state_store)
    end)

    [idp: idp]
  end

  test "accepts a signed LogoutResponse using the HTTP-Redirect binding", %{idp: idp} do
    relay_state = "relay%252Fstate"
    redirect_url = signed_redirect_url(logout_response(), relay_state, idp)

    :get
    |> conn(redirect_url)
    |> assert_signed_out(relay_state)
  end

  test "rejects invalid HTTP-Redirect signatures", %{idp: idp} do
    redirect_url = signed_redirect_url(logout_response(), "relay-state", idp)

    invalid_requests = [
      {String.replace(redirect_url, ~r/Signature=[^&]+/, "Signature=present"), "relay-state"},
      {String.replace(redirect_url, "RelayState=relay-state", "RelayState=modified"), "modified"},
      {redirect_url <> "&Sign%61ture=duplicate", "relay-state"}
    ]

    for {invalid_url, relay_state} <- invalid_requests do
      :get
      |> conn(invalid_url)
      |> assert_invalid_logout_response(relay_state)
    end
  end

  test "rejects an unsigned LogoutResponse using the HTTP-Redirect binding" do
    relay_state = "relay-state"

    redirect_url =
      :esaml_binding.encode_http_redirect(
        ~c"/logout/idp1",
        logout_response(),
        :undefined,
        relay_state
      )

    conn =
      :get
      |> conn(redirect_url)
      |> init_test_session(%{
        "relay_state" => relay_state,
        "idp_id" => "idp1",
        "target_url" => "/signed-out"
      })
      |> SPRouter.call(@router_opts)

    assert conn.status == 403
    assert conn.resp_body == "invalid_request"
  end

  test "accepts a LogoutResponse using the HTTP-POST binding" do
    relay_state = "relay-state"

    saml_response =
      [logout_response()]
      |> :xmerl.export(:xmerl_xml)
      |> IO.iodata_to_binary()
      |> Base.encode64()

    :post
    |> conn("/logout/idp1?SAMLRequest=ignored-query-value", %{
      "SAMLResponse" => saml_response,
      "RelayState" => relay_state
    })
    |> assert_signed_out(relay_state)
  end

  test "accepts a LogoutRequest using the HTTP-Redirect binding", %{idp: idp} do
    relay_state = "relay-state"
    nameid = "user@example.com"
    assertion_key = {"idp1", nameid}

    assertion = assertion(nameid)

    unsigned_sp = Esaml.esaml_sp(idp.esaml_sp_rec, sp_sign_requests: false)

    request =
      :esaml_sp.generate_logout_request(
        ~c"http://samly.howto:4003/sso/sp/logout/idp1",
        String.to_charlist(nameid),
        unsigned_sp
      )

    redirect_url = signed_redirect_url(request, relay_state, idp)

    invalid_conn =
      :get
      |> conn(String.replace(redirect_url, ~r/Signature=[^&]+/, "Signature=invalid"))
      |> init_test_session(%{})
      |> put_private(:samly_nonce, "nonce")
      |> State.put_assertion(assertion_key, assertion)
      |> SPRouter.call(@router_opts)

    assert invalid_conn.status == 403
    assert State.get_assertion(invalid_conn, assertion_key) == assertion

    conn =
      :get
      |> conn(redirect_url)
      |> init_test_session(%{})
      |> put_private(:samly_nonce, "nonce")
      |> State.put_assertion(assertion_key, assertion)
      |> SPRouter.call(@router_opts)

    assert conn.status == 200
    assert conn.resp_body =~ ~s(name="SAMLResponse")
    assert conn.resp_body =~ relay_state
    assert State.get_assertion(conn, assertion_key) == nil
  end

  test "accepts an XML-signed LogoutRequest using the HTTP-POST binding", %{idp: idp} do
    nameid = "post-user@example.com"
    assertion_key = {"idp1", nameid}
    assertion = assertion(nameid)

    request =
      :esaml_sp.generate_logout_request(
        ~c"http://samly.howto:4003/sso/sp/logout/idp1",
        String.to_charlist(nameid),
        idp.esaml_sp_rec
      )

    saml_request =
      [request]
      |> :xmerl.export(:xmerl_xml)
      |> IO.iodata_to_binary()
      |> Base.encode64()

    conn =
      :post
      |> conn("/logout/idp1", %{"SAMLRequest" => saml_request, "RelayState" => "relay-state"})
      |> init_test_session(%{})
      |> put_private(:samly_nonce, "nonce")
      |> State.put_assertion(assertion_key, assertion)
      |> SPRouter.call(@router_opts)

    assert conn.status == 200
    assert State.get_assertion(conn, assertion_key) == nil
  end

  test "rejects ambiguous HTTP-POST logout messages" do
    conn =
      :post
      |> conn("/logout/idp1", %{
        "SAMLRequest" => "request",
        "SAMLResponse" => "response"
      })
      |> init_test_session(%{})
      |> SPRouter.call(@router_opts)

    assert conn.status == 403
    assert conn.resp_body == "invalid_request"
  end

  defp restore_env(key, nil), do: Application.delete_env(:samly, key)
  defp restore_env(key, value), do: Application.put_env(:samly, key, value)

  defp assertion(nameid) do
    %Assertion{
      idp_id: "idp1",
      subject: %Subject{
        name: nameid,
        notonorafter: DateTime.utc_now() |> DateTime.add(1, :hour) |> DateTime.to_iso8601()
      }
    }
  end

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

  defp assert_invalid_logout_response(conn, relay_state) do
    conn =
      conn
      |> init_test_session(%{
        "relay_state" => relay_state,
        "idp_id" => "idp1",
        "target_url" => "/signed-out"
      })
      |> SPRouter.call(@router_opts)

    assert conn.status == 403
    assert conn.resp_body == "invalid_request"
  end

  defp signed_redirect_url(message, relay_state, idp) do
    redirect_url =
      :esaml_binding.encode_http_redirect(
        ~c"/logout/idp1",
        message,
        :undefined,
        relay_state
      )

    encoded_sig_alg = URI.encode_www_form(@rsa_sha256)

    signed_data =
      redirect_url
      |> URI.parse()
      |> Map.fetch!(:query)
      |> String.split("&")
      |> Enum.filter(&String.starts_with?(&1, ["SAMLRequest=", "SAMLResponse=", "RelayState="]))
      |> Kernel.++(["SigAlg=#{encoded_sig_alg}"])
      |> Enum.join("&")

    signature =
      signed_data
      |> :public_key.sign(:sha256, Esaml.esaml_sp(idp.esaml_sp_rec, :key))
      |> Base.encode64()
      |> URI.encode_www_form()

    redirect_url <> "&SigAlg=#{encoded_sig_alg}&Signature=#{signature}"
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
