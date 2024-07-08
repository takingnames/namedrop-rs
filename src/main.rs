use std::error::Error;
use std::io;
use url::Url;
use std::collections::HashMap;

use namedrop;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let nd_client = namedrop::ClientBuilder::new()
        .server_uri("anderspitman.com/namedrop")
        .callback_uri("https://client.anderspitman.com/callback")
        .build();

    let flow = nd_client.start_auth_flow().await?;

    println!("\nBrowse to: {}", flow.get_auth_url());

    //let token = flow.wait_for_token().await;

    let stdin = io::stdin();
    let input = &mut String::new();

    println!("\nEnter callback URI: ");
    let _n = stdin.read_line(input).unwrap();
    let uri = input.trim().to_string();
    let parsed = Url::parse(&uri)?;
    let params: HashMap<_, _> = parsed.query_pairs().into_owned().collect();

    flow.complete(params["code"].clone(), params["state"].clone()).await?;

    return Ok(());
}
