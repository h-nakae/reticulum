defmodule Ret.RemoteOIDCToken do
  @moduledoc """
  This represents an OpenID Connect token returned from a remote service.
  These tokens are never created locally, only ever provided externally and verified locally.
  """
  use Guardian,
    otp_app: :ret,
    secret_fetcher: Ret.RemoteOIDCTokenSecretsFetcher, allowed_algos: ["RS256"]

  def subject_for_token(_, _), do: {:ok, nil}
  def resource_from_claims(_), do: {:ok, nil}
end

defmodule Ret.RemoteOIDCTokenSecretsFetcher do
  @moduledoc """
  This represents the public keys for an OpenID Connect endpoint used to verify tokens.
  The public keys will be configured by an admin for a particular setup. These can not be used for signing.
  """

  def fetch_signing_secret(_mod, _opts) do
    {:error, :not_implemented}
  end

  @spec fetch_verifying_secret(any, any, any) :: {:error, :invalid_key_id | :invalid_token} | {:ok, list | JOSE.JWK.t()}
  def fetch_verifying_secret(mod, %{"kid" => kid, "typ" => "JWT"}, _opts) do
    IO.puts("sssss")
    # TODO implement read through cache that hits discovery endpoint instead of hardcoding keys in config as per https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
    # case Application.get_env(:ret, mod)[:verification_secret_jwk_set]


    case build_url("https://www.googleapis.com/oauth2/v3/certs", %{
      "state" => "closed"
    })
        |> HTTPoison.get!()
        |> Map.get(:body)
        |> Poison.decode!()
        |> Map.get("keys")
        |> Enum.find(&(Map.get(&1, "kid") == kid)) do
      nil -> {:error, :invalid_key_id}
      key -> {:ok, key |> JOSE.JWK.from_map()}
    end
  end

  @doc """
  build url.

  ## Examples

      iex> SampleEx.build_url("http://example.com", %{"foo" => "bar"})
      "http://example.com?foo=bar"

  """
  @spec build_url(String.t(), map()) :: String.t()
  def build_url(path, query) do
    URI.parse(path)
    |> Map.put(:query, URI.encode_query(query))
    |> URI.to_string()
  end

  def fetch_verifying_secret(_mod, _token_headers_, _optss) do
    {:error, :invalid_token}
  end
end
