use std::error::Error;
use std::io;
use url::Url;
use std::collections::HashMap;
use namedrop::FlowCompleteParams;

use namedrop;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let nd_client = namedrop::ClientBuilder::new()
        .server_uri("https://anderspitman.com/namedrop")
        .callback_uri("https://client.anderspitman.com/callback")
        .build()?;

    let flow_data = nd_client.start_auth_flow().await?;

    println!("\nBrowse to: {}", flow_data.auth_url);

    println!("\nEnter callback URI: ");
    let stdin = io::stdin();
    let input = &mut String::new();
    let _n = stdin.read_line(input).unwrap();
    let uri = input.trim().to_string();
    let parsed = Url::parse(&uri)?;
    let params: HashMap<_, _> = parsed.query_pairs().into_owned().collect();

    nd_client.complete_auth_flow(FlowCompleteParams{
        state: flow_data.state,
        pkce_verifier: flow_data.pkce_verifier,
        code: params["code"].clone(),
        callback_state: params["state"].clone(),
    }).await?;

    return Ok(());
}
