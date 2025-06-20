defmodule Samly.IdpData do
  @moduledoc false

  import SweetXml
  require Logger
  require Samly.Esaml
  alias Samly.{Esaml, Helper, IdpData, SpData}

  @type nameid_format :: :unknown | charlist()
  @type certs :: [binary()]
  @type url :: nil | binary()

  defstruct id: "",
            sp_id: "",
            base_url: nil,
            metadata_file: nil,
            metadata: nil,
            pre_session_create_pipeline: nil,
            use_redirect_for_req: false,
            sign_requests: true,
            sign_metadata: true,
            signed_assertion_in_resp: true,
            signed_envelopes_in_resp: true,
            allow_idp_initiated_flow: false,
            allowed_target_urls: [],
            debug_mode: false,
            entity_id: "",
            signed_requests: "",
            certs: [],
            sso_redirect_url: nil,
            sso_post_url: nil,
            slo_redirect_url: nil,
            slo_post_url: nil,
            nameid_format: :unknown,
            fingerprints: [],
            esaml_idp_rec: Esaml.esaml_idp_metadata(),
            esaml_sp_rec: Esaml.esaml_sp(),
            valid?: false,
            force_authn: false

  @type t :: %__MODULE__{
          id: binary(),
          sp_id: binary(),
          base_url: nil | binary(),
          metadata_file: nil | binary(),
          metadata: nil | binary(),
          pre_session_create_pipeline: nil | module(),
          use_redirect_for_req: boolean(),
          sign_requests: boolean(),
          sign_metadata: boolean(),
          signed_assertion_in_resp: boolean(),
          signed_envelopes_in_resp: boolean(),
          allow_idp_initiated_flow: boolean(),
          allowed_target_urls: nil | [binary()],
          debug_mode: boolean(),
          entity_id: binary(),
          signed_requests: binary(),
          certs: certs(),
          sso_redirect_url: url(),
          sso_post_url: url(),
          slo_redirect_url: url(),
          slo_post_url: url(),
          nameid_format: nameid_format(),
          fingerprints: [binary()],
          esaml_idp_rec: :esaml.idp_metadata(),
          esaml_sp_rec: :esaml.sp(),
          valid?: boolean(),
          force_authn: boolean()
        }

  @entdesc "md:EntityDescriptor"
  @idpdesc "md:IDPSSODescriptor"
  @signedreq "WantAuthnRequestsSigned"
  @nameid "md:NameIDFormat"
  @keydesc "md:KeyDescriptor"
  @ssos "md:SingleSignOnService"
  @slos "md:SingleLogoutService"
  @redirect "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
  @post "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

  @entity_id_selector ~x"//#{@entdesc}/@entityID"sl
  @nameid_format_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@nameid}/text()"s
  @req_signed_selector ~x"//#{@entdesc}/#{@idpdesc}/@#{@signedreq}"s
  @sso_redirect_url_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@ssos}[@Binding = '#{@redirect}']/@Location"s
  @sso_post_url_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@ssos}[@Binding = '#{@post}']/@Location"s
  @slo_redirect_url_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@slos}[@Binding = '#{@redirect}']/@Location"s
  @slo_post_url_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@slos}[@Binding = '#{@post}']/@Location"s
  @signing_keys_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@keydesc}[@use != 'encryption']"l
  @enc_keys_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@keydesc}[@use = 'encryption']"l
  @cert_selector ~x"./ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()"s

  @type id :: binary()

  @spec load_providers([map], %{required(id()) => %SpData{}}) ::
          %{required(id()) => %IdpData{}} | no_return()
  def load_providers(prov_config, service_providers) do
    prov_config
    |> Enum.map(fn idp_config -> load_provider(idp_config, service_providers) end)
    |> Enum.filter(fn idp_data -> idp_data.valid? end)
    |> Enum.map(fn idp_data -> {idp_data.id, idp_data} end)
    |> Enum.into(%{})
  end

  @spec load_provider(map(), %{required(id()) => %SpData{}}) :: %IdpData{} | no_return
  def load_provider(idp_config, service_providers) do
    %IdpData{}
    |> save_idp_config(idp_config)
    |> load_metadata()
    |> override_nameid_format(idp_config)
    |> update_esaml_recs(service_providers, idp_config)
    |> verify_slo_url()
  end

  @spec save_idp_config(%IdpData{}, map()) :: %IdpData{}
  defp save_idp_config(idp_data, %{id: id, sp_id: sp_id} = opts_map)
       when is_binary(id) and is_binary(sp_id) do
    %IdpData{idp_data | id: id, sp_id: sp_id, base_url: Map.get(opts_map, :base_url)}
    |> set_metadata(opts_map)
    |> set_pipeline(opts_map)
    |> set_allowed_target_urls(opts_map)
    |> set_boolean_attr(opts_map, :use_redirect_for_req)
    |> set_boolean_attr(opts_map, :sign_requests)
    |> set_boolean_attr(opts_map, :sign_metadata)
    |> set_boolean_attr(opts_map, :signed_assertion_in_resp)
    |> set_boolean_attr(opts_map, :signed_envelopes_in_resp)
    |> set_boolean_attr(opts_map, :allow_idp_initiated_flow)
    |> set_boolean_attr(opts_map, :force_authn)
    |> set_boolean_attr(opts_map, :debug_mode)
  end

  @spec load_metadata(%IdpData{}) :: %IdpData{}
  defp load_metadata(idp_data = %IdpData{metadata: metadata}) when not is_nil(metadata),
    do: from_xml(metadata, idp_data)

  defp load_metadata(idp_data = %IdpData{metadata_file: metadata_file})
       when not is_nil(metadata_file) do
    case File.read(idp_data.metadata_file) do
      {:ok, metadata} ->
        load_metadata(%{idp_data | metadata: metadata})

      {:error, reason} ->
        Logger.error(
          "[Samly] Failed to read metadata_file [#{inspect(idp_data.metadata_file)}]: #{inspect(reason)}"
        )

        idp_data
    end
  end

  defp load_metadata(idp_data) do
    Logger.error(
      "[Samly] Either `metadata` or `metadata_file` must be specified in the IdP configuration"
    )

    idp_data
  end

  @spec update_esaml_recs(%IdpData{}, %{required(id()) => %SpData{}}, map()) :: %IdpData{}
  defp update_esaml_recs(idp_data, service_providers, opts_map) do
    case Map.get(service_providers, idp_data.sp_id) do
      %SpData{} = sp ->
        idp_data = %IdpData{idp_data | esaml_idp_rec: to_esaml_idp_metadata(idp_data, opts_map)}
        idp_data = %IdpData{idp_data | esaml_sp_rec: get_esaml_sp(sp, idp_data)}
        %IdpData{idp_data | valid?: cert_config_ok?(idp_data, sp)}

      _ ->
        Logger.error("[Samly] Unknown/invalid sp_id: #{idp_data.sp_id}")
        idp_data
    end
  end

  @spec cert_config_ok?(%IdpData{}, %SpData{}) :: boolean
  defp cert_config_ok?(%IdpData{} = idp_data, %SpData{} = sp_data) do
    if (idp_data.sign_metadata || idp_data.sign_requests) &&
         (sp_data.cert == :undefined || sp_data.key == :undefined) do
      Logger.error("[Samly] SP cert or key missing - Skipping identity provider: #{idp_data.id}")
      false
    else
      true
    end
  end

  @spec verify_slo_url(%IdpData{}) :: %IdpData{}
  defp verify_slo_url(%IdpData{} = idp_data) do
    if idp_data.valid? && idp_data.slo_redirect_url == nil && idp_data.slo_post_url == nil do
      Logger.warning("[Samly] SLO Endpoint missing in [#{inspect(idp_data.metadata_file)}]")
    end

    idp_data
  end

  @default_metadata_file "idp_metadata.xml"

  @spec set_metadata(%IdpData{}, map()) :: %IdpData{}
  defp set_metadata(%IdpData{} = idp_data, %{} = opts_map) do
    %IdpData{
      idp_data
      | metadata_file: Map.get(opts_map, :metadata_file, @default_metadata_file),
        metadata: opts_map[:metadata]
    }
  end

  @spec set_pipeline(%IdpData{}, map()) :: %IdpData{}
  defp set_pipeline(%IdpData{} = idp_data, %{} = opts_map) do
    pipeline = Map.get(opts_map, :pre_session_create_pipeline)
    %IdpData{idp_data | pre_session_create_pipeline: pipeline}
  end

  defp set_allowed_target_urls(%IdpData{} = idp_data, %{} = opts_map) do
    target_urls =
      case Map.get(opts_map, :allowed_target_urls, nil) do
        nil -> nil
        urls when is_list(urls) -> Enum.filter(urls, &is_binary/1)
      end

    %IdpData{idp_data | allowed_target_urls: target_urls}
  end

  @spec override_nameid_format(%IdpData{}, map()) :: %IdpData{}
  defp override_nameid_format(%IdpData{} = idp_data, idp_config) do
    nameid_format =
      case Map.get(idp_config, :nameid_format, "") do
        "" ->
          idp_data.nameid_format

        format when is_binary(format) ->
          to_charlist(format)

        :email ->
          ~c"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

        :x509 ->
          ~c"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"

        :windows ->
          ~c"urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"

        :krb ->
          ~c"urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"

        :persistent ->
          ~c"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

        :transient ->
          ~c"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

        invalid_nameid_format ->
          Logger.error(
            "[Samly] invalid nameid_format [#{inspect(idp_data.metadata_file)}]: #{inspect(invalid_nameid_format)}"
          )

          idp_data.nameid_format
      end

    %IdpData{idp_data | nameid_format: nameid_format}
  end

  @spec set_boolean_attr(%IdpData{}, map(), atom()) :: %IdpData{}
  defp set_boolean_attr(%IdpData{} = idp_data, %{} = opts_map, attr_name)
       when is_atom(attr_name) do
    v = Map.get(opts_map, attr_name)
    if is_boolean(v), do: Map.put(idp_data, attr_name, v), else: idp_data
  end

  @spec from_xml(binary, %IdpData{}) :: %IdpData{}
  defp from_xml(metadata_xml, idp_data) when is_binary(metadata_xml) do
    xml_opts = [
      space: :normalize,
      namespace_conformant: true,
      comments: false,
      default_attrs: true
    ]

    md_xml = SweetXml.parse(metadata_xml, xml_opts)
    signing_certs = get_signing_certs(md_xml)

    %IdpData{
      idp_data
      | entity_id: get_entity_id(md_xml),
        signed_requests: get_req_signed(md_xml),
        certs: signing_certs,
        fingerprints: idp_cert_fingerprints(signing_certs),
        sso_redirect_url: get_sso_redirect_url(md_xml),
        sso_post_url: get_sso_post_url(md_xml),
        slo_redirect_url: get_slo_redirect_url(md_xml),
        slo_post_url: get_slo_post_url(md_xml),
        nameid_format: get_nameid_format(md_xml)
    }
  end

  # @spec to_esaml_idp_metadata(IdpData.t(), map()) :: :esaml_idp_metadata
  defp to_esaml_idp_metadata(%IdpData{} = idp_data, %{} = idp_config) do
    {sso_url, slo_url} = get_sso_slo_urls(idp_data, idp_config)
    sso_url = if sso_url, do: String.to_charlist(sso_url), else: []
    slo_url = if slo_url, do: String.to_charlist(slo_url), else: :undefined

    Esaml.esaml_idp_metadata(
      entity_id: String.to_charlist(idp_data.entity_id),
      login_location: sso_url,
      logout_location: slo_url,
      name_format: idp_data.nameid_format
    )
  end

  defp get_sso_slo_urls(%IdpData{} = idp_data, %{use_redirect_for_req: true}) do
    {idp_data.sso_redirect_url, idp_data.slo_redirect_url}
  end

  defp get_sso_slo_urls(%IdpData{} = idp_data, %{use_redirect_for_req: false}) do
    {idp_data.sso_post_url, idp_data.slo_post_url}
  end

  defp get_sso_slo_urls(%IdpData{} = idp_data, _opts_map) do
    {
      idp_data.sso_post_url || idp_data.sso_redirect_url,
      idp_data.slo_post_url || idp_data.slo_redirect_url
    }
  end

  @spec idp_cert_fingerprints(certs()) :: [binary()]
  defp idp_cert_fingerprints(certs) when is_list(certs) do
    certs
    |> Enum.map(&Base.decode64!/1)
    |> Enum.map(&cert_fingerprint/1)
    |> Enum.map(&String.to_charlist/1)
    |> :esaml_util.convert_fingerprints()
  end

  defp cert_fingerprint(dercert) do
    "sha256:" <> (:sha256 |> :crypto.hash(dercert) |> Base.encode64())
  end

  # @spec get_esaml_sp(%SpData{}, %IdpData{}) :: :esaml_sp
  defp get_esaml_sp(%SpData{} = sp_data, %IdpData{} = idp_data) do
    idp_id_from = Application.get_env(:samly, :idp_id_from)
    path_segment_idp_id = if idp_id_from == :subdomain, do: nil, else: idp_data.id

    sp_entity_id =
      case sp_data.entity_id do
        "" -> :undefined
        id -> String.to_charlist(id)
      end

    Esaml.esaml_sp(
      org:
        Esaml.esaml_org(
          name: String.to_charlist(sp_data.org_name),
          displayname: String.to_charlist(sp_data.org_displayname),
          url: String.to_charlist(sp_data.org_url)
        ),
      tech:
        Esaml.esaml_contact(
          name: String.to_charlist(sp_data.contact_name),
          email: String.to_charlist(sp_data.contact_email)
        ),
      key: sp_data.key,
      certificate: sp_data.cert,
      sp_sign_requests: idp_data.sign_requests,
      sp_sign_metadata: idp_data.sign_metadata,
      idp_signs_envelopes: idp_data.signed_envelopes_in_resp,
      idp_signs_assertions: idp_data.signed_assertion_in_resp,
      trusted_fingerprints: idp_data.fingerprints,
      metadata_uri: Helper.get_metadata_uri(idp_data.base_url, path_segment_idp_id),
      consume_uri: Helper.get_consume_uri(idp_data.base_url, path_segment_idp_id),
      logout_uri: Helper.get_logout_uri(idp_data.base_url, path_segment_idp_id),
      entity_id: sp_entity_id
    )
  end

  @spec get_entity_id(SweetXml.xmlElement()) :: binary()
  def get_entity_id(md_elem) do
    md_elem |> xpath(@entity_id_selector |> add_ns()) |> hd() |> String.trim()
  end

  @spec get_nameid_format(SweetXml.xmlElement()) :: nameid_format()
  def get_nameid_format(md_elem) do
    case get_data(md_elem, @nameid_format_selector) do
      "" -> :unknown
      nameid_format -> to_charlist(nameid_format)
    end
  end

  @spec get_req_signed(SweetXml.xmlElement()) :: binary()
  def get_req_signed(md_elem), do: get_data(md_elem, @req_signed_selector)

  @spec get_signing_certs(SweetXml.xmlElement()) :: certs()
  def get_signing_certs(md_elem), do: get_certs(md_elem, @signing_keys_selector)

  @spec get_enc_certs(SweetXml.xmlElement()) :: certs()
  def get_enc_certs(md_elem), do: get_certs(md_elem, @enc_keys_selector)

  @spec get_certs(SweetXml.xmlElement(), %SweetXpath{}) :: certs()
  defp get_certs(md_elem, key_selector) do
    md_elem
    |> xpath(key_selector |> add_ns())
    |> Enum.map(fn e ->
      # Extract base64 encoded cert from XML (strip away any whitespace)
      cert = xpath(e, @cert_selector |> add_ns())

      cert
      |> String.split()
      |> Enum.map(&String.trim/1)
      |> Enum.join()
    end)
  end

  @spec get_sso_redirect_url(SweetXml.xmlElement()) :: url()
  def get_sso_redirect_url(md_elem), do: get_url(md_elem, @sso_redirect_url_selector)

  @spec get_sso_post_url(SweetXml.xmlElement()) :: url()
  def get_sso_post_url(md_elem), do: get_url(md_elem, @sso_post_url_selector)

  @spec get_slo_redirect_url(SweetXml.xmlElement()) :: url()
  def get_slo_redirect_url(md_elem), do: get_url(md_elem, @slo_redirect_url_selector)

  @spec get_slo_post_url(SweetXml.xmlElement()) :: url()
  def get_slo_post_url(md_elem), do: get_url(md_elem, @slo_post_url_selector)

  @spec get_url(SweetXml.xmlElement(), %SweetXpath{}) :: url()
  defp get_url(md_elem, selector) do
    case get_data(md_elem, selector) do
      "" -> nil
      url -> url
    end
  end

  @spec get_data(SweetXml.xmlElement(), %SweetXpath{}) :: binary()
  def get_data(md_elem, selector) do
    md_elem |> xpath(selector |> add_ns()) |> String.trim()
  end

  @spec add_ns(%SweetXpath{}) :: %SweetXpath{}
  defp add_ns(xpath) do
    xpath
    |> SweetXml.add_namespace("md", "urn:oasis:names:tc:SAML:2.0:metadata")
    |> SweetXml.add_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
  end
end
