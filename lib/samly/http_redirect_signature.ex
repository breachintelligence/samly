defmodule Samly.HTTPRedirectSignature do
  @moduledoc false

  @signature_algorithms %{
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => :sha256,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => :sha384,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => :sha512
  }
  @saml_params ~w(SAMLRequest SAMLResponse RelayState SigAlg Signature)

  @type message_type :: :request | :response

  @spec verify(binary(), [binary()]) ::
          {:ok, message_type()} | {:error, :invalid_signature}
  def verify(query_string, signing_certs)
      when is_binary(query_string) and is_list(signing_certs) do
    with {:ok, params} <- parse_params(query_string),
         {:ok, message_type, message_name, encoded_message} <- message(params),
         {:ok, encoded_algorithm} <- required_param(params, "SigAlg"),
         {:ok, encoded_signature} <- required_param(params, "Signature"),
         {:ok, digest_type} <- signature_algorithm(encoded_algorithm),
         {:ok, signature} <- decode_signature(encoded_signature),
         signed_data =
           signed_data(message_name, encoded_message, params["RelayState"], encoded_algorithm),
         true <-
           Enum.any?(signing_certs, fn cert ->
             valid_signature?(signed_data, digest_type, signature, cert)
           end) do
      {:ok, message_type}
    else
      _ -> {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  def verify(_query_string, _signing_certs), do: {:error, :invalid_signature}

  defp parse_params(query_string) do
    query_string
    |> String.split("&")
    |> Enum.reduce_while({:ok, %{}}, &parse_param/2)
  end

  defp parse_param(pair, {:ok, params}) do
    {encoded_name, value} =
      case String.split(pair, "=", parts: 2) do
        [name, value] -> {name, value}
        [name] -> {name, ""}
      end

    name = URI.decode_www_form(encoded_name)

    cond do
      nested_saml_param?(name) ->
        {:halt, {:error, :invalid_parameter}}

      name not in @saml_params ->
        {:cont, {:ok, params}}

      encoded_name != name or Map.has_key?(params, name) ->
        {:halt, {:error, :invalid_parameter}}

      true ->
        {:cont, {:ok, Map.put(params, name, value)}}
    end
  end

  # Plug treats `RelayState[]` and `RelayState[key]` as variants of
  # `RelayState`. Reject them here so downstream query parsing cannot replace
  # an authenticated value with an unsigned one.
  defp nested_saml_param?(name) do
    Enum.any?(@saml_params, fn param ->
      String.starts_with?(name, param <> "[")
    end)
  end

  defp message(params) do
    case {Map.fetch(params, "SAMLRequest"), Map.fetch(params, "SAMLResponse")} do
      {{:ok, request}, :error} when request != "" ->
        {:ok, :request, "SAMLRequest", request}

      {:error, {:ok, response}} when response != "" ->
        {:ok, :response, "SAMLResponse", response}

      _ ->
        {:error, :invalid_message}
    end
  end

  defp required_param(params, name) do
    case params[name] do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :missing_parameter}
    end
  end

  defp signature_algorithm(encoded_algorithm) do
    case Map.fetch(@signature_algorithms, URI.decode_www_form(encoded_algorithm)) do
      {:ok, digest_type} -> {:ok, digest_type}
      :error -> {:error, :unsupported_algorithm}
    end
  end

  defp decode_signature(encoded_signature) do
    encoded_signature
    |> URI.decode_www_form()
    |> Base.decode64()
  end

  defp signed_data(message_name, message, nil, algorithm) do
    "#{message_name}=#{message}&SigAlg=#{algorithm}"
  end

  defp signed_data(message_name, message, relay_state, algorithm) do
    "#{message_name}=#{message}&RelayState=#{relay_state}&SigAlg=#{algorithm}"
  end

  defp valid_signature?(signed_data, digest_type, signature, encoded_cert) do
    with {:ok, cert} <- Base.decode64(encoded_cert),
         {:ok, public_key} <- public_key(cert) do
      :public_key.verify(signed_data, digest_type, signature, public_key)
    else
      _ -> false
    end
  rescue
    _ -> false
  end

  defp public_key(cert) do
    case :public_key.pkix_decode_cert(cert, :otp) do
      {:OTPCertificate,
       {:OTPTBSCertificate, _, _, _, _, _, _, {:OTPSubjectPublicKeyInfo, _, public_key}, _, _, _},
       _, _} ->
        {:ok, public_key}

      _ ->
        {:error, :invalid_certificate}
    end
  end
end
