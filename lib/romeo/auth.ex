defmodule Romeo.Auth do
  @moduledoc """
  Handles XMPP authentication mechanisms.
  """

  use Romeo.XML
  require Logger

  defmodule Error do
    defexception [:message]

    def exception(mechanism) do
      msg = "Failed to authenticate using mechanism: #{inspect mechanism}"
      %Romeo.Auth.Error{message: msg}
    end
  end

  @doc """
  Authenticates the client using the configured preferred mechanism.

  If the preferred mechanism is not supported it will choose PLAIN.
  """
  def authenticate!(conn) do
    preferred  = conn.preferred_auth_mechanisms
    mechanisms = conn.features.mechanisms
    preferred_mechanism(preferred, mechanisms) |> do_authenticate(conn)
  end

  def handshake!(%{transport: mod, password: password, stream_id: stream_id} = conn) do
    stanza =
      :crypto.hash(:sha, "#{stream_id}#{password}")
      |> Base.encode16(case: :lower)
      |> Stanza.handshake()

    conn
    |> mod.send(stanza)
    |> mod.recv(fn
      conn, xmlel(name: "handshake") ->
        conn
      _conn, xmlel(name: "stream:error") ->
        raise Romeo.Auth.Error, "handshake error"
    end)
  end


  defp do_authenticate(mechanism, conn) do
    Logger.info fn -> "Authenticating with #{mechanism}" end
    authenticate_with(mechanism, conn)
    case success?(conn) do
      {:ok, conn} -> conn
      {:error, _conn} -> raise Romeo.Auth.Error, mechanism
    end
  end

  defp authenticate_with("PLAIN", %{transport: mod} = conn) do
    [username, password] = get_client_credentials(conn)
    payload = <<0>> <> username <> <<0>> <> password
    mod.send(conn, Romeo.Stanza.auth("PLAIN", Romeo.Stanza.base64_cdata(payload)))
  end

  defp authenticate_with("X-OAUTH2", %{transport: mod, jid: jid, password: password} = conn) do
    payload = <<0>> <> jid <> <<0>> <> password
    additional_attrs = [{"auth:service", "oauth2"}, {"xmlns:auth", "http://www.google.com/talk/protocol/auth"}]
    mod.send(conn, Romeo.Stanza.auth("X-OAUTH2", Romeo.Stanza.base64_cdata(payload), additional_attrs))
  end

  defp authenticate_with("DIGEST-MD5", _conn) do
    raise "Not implemented"
  end

  defp authenticate_with("SCRAM-SHA-1", _conn) do
    raise "Not implemented"
  end

  defp authenticate_with("ANONYMOUS", %{transport: mod} = conn) do
    conn |> mod.send(Romeo.Stanza.auth("ANONYMOUS"))
  end

  defp authenticate_with("EXTERNAL", _conn) do
    raise "Not implemented"
  end

  defp success?(%{transport: mod} = conn) do
    mod.recv(conn, fn conn, xmlel(name: name) ->
      case name do
        "success" ->
          Logger.info fn -> "Authenticated successfully" end
          {:ok, conn}
        "failure" ->
          {:error, conn}
      end
    end)
  end

  defp get_client_credentials(%{jid: jid, password: password}) do
    [Romeo.JID.parse(jid).user, password]
  end

  defp preferred_mechanism([], _), do: "PLAIN"
  defp preferred_mechanism([h|t], mechanisms) do
    case Enum.member?(mechanisms, h) do
      true  -> h
      false -> preferred_mechanism(t, mechanisms)
    end
  end
end
