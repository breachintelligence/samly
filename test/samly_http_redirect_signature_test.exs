defmodule SamlyHTTPRedirectSignatureTest do
  use ExUnit.Case, async: true

  alias Samly.{HTTPRedirectSignature, SpData}

  @algorithms [
    {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", :sha256},
    {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", :sha384},
    {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", :sha512}
  ]

  setup_all do
    sp =
      SpData.load_provider(%{
        id: "sp1",
        entity_id: "urn:test:sp1",
        certfile: "test/data/test.crt",
        keyfile: "test/data/test.pem"
      })

    [key: sp.key, certs: [Base.encode64(sp.cert)]]
  end

  test "verifies request and response signatures without normalizing encoded values", context do
    for message_type <- [:request, :response] do
      query =
        signed_query(message_type, "payload+/=", context.key, relay_state: "a value/%25")

      assert HTTPRedirectSignature.verify(query, context.certs) == {:ok, message_type}
    end
  end

  test "supports modern RSA digest algorithms", context do
    for {algorithm, digest_type} <- @algorithms do
      query =
        signed_query(:response, "payload", context.key,
          algorithm: algorithm,
          digest_type: digest_type
        )

      assert HTTPRedirectSignature.verify(query, context.certs) == {:ok, :response}
    end
  end

  test "verifies messages without RelayState", context do
    query = signed_query(:response, "payload", context.key)

    assert HTTPRedirectSignature.verify(query, context.certs) == {:ok, :response}
  end

  test "rejects missing, ambiguous, duplicate, or noncanonical parameters", context do
    valid_query = signed_query(:response, "payload", context.key)
    encoded_sig_alg = URI.encode_www_form(elem(hd(@algorithms), 0))

    invalid_queries = [
      "",
      "SAMLResponse=payload",
      "SAMLResponse=&SigAlg=#{encoded_sig_alg}&Signature=present",
      valid_query <> "&SAMLRequest=request",
      valid_query <> "&SAMLRequest=",
      valid_query <> "&SAMLResponse=duplicate",
      valid_query <> "&Sign%61ture=duplicate",
      String.replace(valid_query, "SAMLResponse", "%53AMLResponse")
    ]

    for query <- invalid_queries do
      assert HTTPRedirectSignature.verify(query, context.certs) ==
               {:error, :invalid_signature}
    end
  end

  test "rejects tampering, weak algorithms, and untrusted certificates", context do
    valid_query = signed_query(:response, "payload", context.key, relay_state: "relay-state")

    invalid_queries = [
      String.replace(valid_query, "payload", "modified"),
      String.replace(valid_query, "relay-state", "modified"),
      String.replace(valid_query, ~r/Signature=[^&]+/, "Signature=present"),
      signed_query(:response, "payload", context.key,
        algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        digest_type: :sha
      )
    ]

    for query <- invalid_queries do
      assert HTTPRedirectSignature.verify(query, context.certs) ==
               {:error, :invalid_signature}
    end

    assert HTTPRedirectSignature.verify(valid_query, []) == {:error, :invalid_signature}

    assert HTTPRedirectSignature.verify(valid_query, ["not-a-certificate"]) ==
             {:error, :invalid_signature}
  end

  defp signed_query(message_type, message, key, opts \\ []) do
    message_name = if message_type == :request, do: "SAMLRequest", else: "SAMLResponse"
    algorithm = Keyword.get(opts, :algorithm, elem(hd(@algorithms), 0))
    digest_type = Keyword.get(opts, :digest_type, elem(hd(@algorithms), 1))

    signed_params = [
      "#{message_name}=#{URI.encode_www_form(message)}",
      relay_state_param(opts),
      "SigAlg=#{URI.encode_www_form(algorithm)}"
    ]

    signed_data = signed_params |> Enum.reject(&is_nil/1) |> Enum.join("&")

    signature =
      signed_data
      |> :public_key.sign(digest_type, key)
      |> Base.encode64()
      |> URI.encode_www_form()

    signed_data <> "&Signature=#{signature}"
  end

  defp relay_state_param(opts) do
    case Keyword.fetch(opts, :relay_state) do
      {:ok, relay_state} -> "RelayState=#{URI.encode_www_form(relay_state)}"
      :error -> nil
    end
  end
end
