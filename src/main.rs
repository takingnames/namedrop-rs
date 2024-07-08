use std::error::Error;
use std::io;

use namedrop;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let nd_client = namedrop::ClientBuilder::new()
        .server_uri("anderspitman.com/namedrop")
        .callback_uri("https://client.anderspitman.com/callback")
        .build();

    let flow = nd_client.start_auth_flow().await?;

    println!("Browse to: {}", flow.get_auth_url());

    //let token = flow.wait_for_token().await;

    let stdin = io::stdin();
    let input = &mut String::new();

    println!("Enter code: ");
    let _n = stdin.read_line(input).unwrap();
    let code = input.trim().to_string();

    *input = "".to_string();

    println!("Enter state: ");
    let _n = stdin.read_line(input).unwrap();
    let state = input.trim().to_string();

    flow.complete(code, state).await?;

    return Ok(());
}
