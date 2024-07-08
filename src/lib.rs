use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenUrl, TokenResponse
};
use url::Url;

use std::fmt;
use std::result;

#[derive(Debug, Clone)]
pub struct Error {
    reason: String,
}

type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for Error {}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error{
            reason: err.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct Client {
    oauth_client: BasicClient,
}

impl Client {
    pub async fn start_auth_flow(&self) -> Result<FlowData> {
        
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        println!("code challenge:");
        dbg!(&pkce_challenge);

        let (auth_url, csrf_token) = self.oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("subdomain".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(FlowData {
            auth_url,
            state: csrf_token.secret().clone(),
            pkce_verifier: pkce_verifier.secret().to_string(),
        })
    }

    pub async fn complete_auth_flow(&self, params: FlowCompleteParams) -> Result<TokenData> {

        if params.callback_state != params.state {
            return Err(Error{
                reason: "Invalid state".to_string(),
            });
        }

        let pkce_verifier = PkceCodeVerifier::new(params.pkce_verifier);

        println!("send code verif:");
        dbg!(&pkce_verifier.secret());

        let token = self
            .oauth_client
            .exchange_code(AuthorizationCode::new(params.code.trim().into()))
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client)
            .await.map_err(|err| Error{
                reason: err.to_string(),
            })?;

        Ok(TokenData{
            token: token.access_token().secret().to_owned(),
            permissions: Vec::new(),
        })
    }
}

#[derive(Debug)]
pub struct FlowData {
    pub auth_url: Url,
    pub state: String,
    pub pkce_verifier: String,
}

#[derive(Debug)]
pub struct FlowCompleteParams {
    pub state: String,
    pub pkce_verifier: String,
    pub code: String,
    pub callback_state: String,
}

#[derive(Debug)]
pub struct TokenData {
    pub token: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug)]
pub struct Permission {
    pub domain: String,
    pub host: String,
}


#[derive(Debug)]
pub struct ClientBuilder {
    server_uri: String,
    client_domain: String,
    callback_server: bool,
    callback_uri: String,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            server_uri: "".to_string(),
            client_domain: "".to_string(),
            callback_server: false,
            callback_uri: "".to_string(),
        }
    }

    pub fn server_uri<T: Into<String>>(&mut self, uri: T) -> &mut Self {
        self.server_uri = uri.into();
        self
    }

    pub fn client_domain<T: Into<String>>(&mut self, domain: T) -> &mut Self {
        self.client_domain = domain.into();
        self
    }

    pub fn callback_server(&mut self) -> &mut Self {
        self.callback_server = true;
        self
    }

    pub fn callback_uri<T: Into<String>>(&mut self, uri: T) -> &mut Self {
        self.callback_uri = uri.into();
        self
    }

    pub fn build(&self) -> Result<Client> {

        let server_uri = match self.server_uri.as_str() {
            "" => "https://takingnames.io/namedrop".to_string(),
            _ => self.server_uri.clone(),
        };

        let parsed = Url::parse(&self.callback_uri)?;
        let client_domain = parsed.host().ok_or(Error{
            reason: "Missing client domain".to_string(),
        })?;
        let client_scheme = parsed.scheme();

        let port_str = match parsed.port() {
            Some(port) => format!(":{}", port),
            None => "".to_string(),
        };

        let client = BasicClient::new(
            ClientId::new(format!("{}://{}{}", client_scheme, client_domain, port_str)),
            Some(ClientSecret::new("".to_string())),
            AuthUrl::new(format!("{}/authorize", server_uri))?,
            Some(TokenUrl::new(format!("{}/token", server_uri))?),
        )
        .set_redirect_uri(RedirectUrl::new(self.callback_uri.clone())?);

        Ok(Client {
            oauth_client: client,
        })
    }
}
