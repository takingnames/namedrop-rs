use oauth2::RequestTokenError::{ServerResponse,Request,Parse,Other};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use url::Url;

use axum::{
    extract::{Query, State},
    routing::get,
    Router,
};
use serde::Deserialize;

use std::sync::Arc;
use std::error::Error;
use std::fmt;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;

struct AppState {
    tx: mpsc::Sender<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Params {
    #[serde(default)]
    code: String,
}

#[derive(Debug)]
pub struct Client {
    server_domain: String,
    callback_uri: String,
}

impl Client {
    pub async fn start_auth_flow(&self) -> Flow {
        let server_domain = match self.server_domain.as_str() {
            "" => "takingnames.io".to_string(),
            _ => self.server_domain.clone(),
        };

        let mut code_rx = None;
        let callback_uri;
        if self.callback_uri.is_empty() {
            let (tx, rx) = mpsc::channel(8);
            code_rx = Some(rx);

            let app_state = Arc::new(AppState { tx });

            let app = Router::new()
                .route("/callback", get(handler))
                .with_state(app_state);
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let port = &listener.local_addr().unwrap().port();

            callback_uri = format!("http://localhost:{}/callback", port);

            tokio::spawn(async {
                println!("Start server");
                axum::serve(listener, app).await.unwrap();
            });
        } else {
            callback_uri = self.callback_uri.clone();
        }

        let parsed = Url::parse(&callback_uri).unwrap();
        let client_domain = parsed.host().unwrap();
        let client_scheme = parsed.scheme();

        let port_str = match parsed.port() {
            Some(port) => format!(":{}", port),
            None => "".to_string(),
        };

        let server = format!("https://{}", server_domain);

        let client = BasicClient::new(
            ClientId::new(format!("{}://{}{}", client_scheme, client_domain, port_str)),
            Some(ClientSecret::new("".to_string())),
            AuthUrl::new(format!("{}/namedrop/authorize", server)).unwrap(),
            Some(TokenUrl::new(format!("{}/namedrop/token", server)).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(callback_uri.clone()).unwrap());

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        println!("code challenge:");
        dbg!(&pkce_challenge);

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("subdomain".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        Flow {
            auth_url,
            state: csrf_token.secret().clone(),
            pkce_verifier,
            oauth_client: client,
            code_rx,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowError {
    reason: String,
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl Error for FlowError {
}

#[derive(Debug)]
pub struct Flow {
    auth_url: Url,
    state: String,
    pkce_verifier: PkceCodeVerifier,
    oauth_client: BasicClient,
    code_rx: Option<Receiver<String>>,
}

impl Flow {
    pub fn get_auth_url(&self) -> String {
        self.auth_url.to_string()
    }

    //pub async fn wait_for_token(&mut self) {
    //    let code = self.code_rx.as_mut().unwrap().recv().await.unwrap();

    //    println!("Authorization code: {}", code);

    //    self.complete(code, "".to_string()).await
    //}

    pub async fn complete(&self, code: String, state: String) -> Result<(), Box<dyn Error>> {

        if state != self.state {
            return Err(Box::new(FlowError{
                reason: "Invalid state".to_string(),
            }));
        }

        let pkce_verifier = PkceCodeVerifier::new(self.pkce_verifier.secret().to_string());

        println!("send code verif:");
        dbg!(&pkce_verifier.secret());

        let token = self
            .oauth_client
            .exchange_code(AuthorizationCode::new(code.trim().into()))
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client)
            .await?;

        dbg!(&token);

        //match &token_result {
        //    Ok(r) => println!("{:?}", r),
        //    Err(e) => {
        //        match e {
        //            ServerResponse(s) => {
        //                println!("here1: {}", s);
        //            },
        //            Request(s) => {
        //                println!("here2: {}", s);
        //            },
        //            Parse(_, b) => {
        //                println!("here3: {}", String::from_utf8_lossy(b));
        //            },
        //            Other(s) => {
        //                println!("here4: {}", s);
        //            },
        //        }
        //    }
        //};

        //tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

        //let ref_token_result = self
        //    .oauth_client
        //    .exchange_refresh_token(token_result.unwrap().refresh_token().unwrap())
        //    .request_async(async_http_client)
        //    .await;

        //match &ref_token_result {
        //    Ok(r) => println!("{:?}", r),
        //    Err(e) => {
        //        match e {
        //            ServerResponse(s) => {
        //                println!("here1: {}", s);
        //            },
        //            Request(s) => {
        //                println!("here2: {}", s);
        //            },
        //            Parse(_, b) => {
        //                println!("here3: {}", String::from_utf8_lossy(b));
        //            },
        //            Other(s) => {
        //                println!("here4: {}", s);
        //            },
        //        }
        //    }
        //};

        Ok(())
    }
}

#[derive(Debug)]
pub struct ClientBuilder {
    server_domain: String,
    client_domain: String,
    callback_server: bool,
    callback_uri: String,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            server_domain: "".to_string(),
            client_domain: "".to_string(),
            callback_server: false,
            callback_uri: "".to_string(),
        }
    }

    pub fn server_domain<T: Into<String>>(&mut self, domain: T) -> &mut Self {
        self.server_domain = domain.into();
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

    pub fn build(&self) -> Client {
        Client {
            server_domain: self.server_domain.clone(),
            callback_uri: self.callback_uri.clone(),
        }
    }
}

async fn handler(State(state): State<Arc<AppState>>, Query(params): Query<Params>) -> String {
    state.tx.send(params.code.clone()).await.unwrap();

    format!("{params:?}")
}
