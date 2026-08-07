defmodule Samly.SPRouter do
  @moduledoc false

  use Plug.Router
  import Plug.Conn
  import Samly.RouterUtil, only: [check_idp_id: 2]

  plug :fetch_session
  plug :fetch_query_params
  plug :match
  plug :check_idp_id
  plug :dispatch

  get "/metadata/*idp_id_seg" do
    # TODO: Make a release task to generate SP metadata
    conn |> Samly.SPHandler.send_metadata()
  end

  post "/consume/*idp_id_seg" do
    conn |> Samly.SPHandler.consume_signin_response()
  end

  get "/logout/*idp_id_seg" do
    case Samly.HTTPRedirectSignature.verify(conn.query_string, conn.private.samly_idp.certs) do
      {:ok, :response} ->
        Samly.SPHandler.handle_logout_response(conn)

      {:ok, :request} ->
        conn
        |> put_private(:samly_http_redirect_signature_verified, true)
        |> Samly.SPHandler.handle_logout_request()

      {:error, :invalid_signature} ->
        send_resp(conn, 403, "invalid_request")
    end
  end

  post "/logout/*idp_id_seg" do
    case logout_message(conn.body_params) do
      :response -> Samly.SPHandler.handle_logout_response(conn)
      :request -> Samly.SPHandler.handle_logout_request(conn)
      :invalid -> send_resp(conn, 403, "invalid_request")
    end
  end

  match _ do
    conn |> send_resp(404, "not_found")
  end

  defp logout_message(params) do
    case {params["SAMLRequest"], params["SAMLResponse"]} do
      {request, nil} when is_binary(request) and request != "" -> :request
      {nil, response} when is_binary(response) and response != "" -> :response
      _ -> :invalid
    end
  end
end
