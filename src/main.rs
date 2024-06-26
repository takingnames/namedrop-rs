use std::error::Error;
use std::io;

use namedrop;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let nd_client = namedrop::ClientBuilder::new()
        .server_domain("anderspitman.com")
        //.callback_uri("https://client.anderspitman.com/callback")
        .build();

    let mut flow = nd_client.start_auth_flow().await;

    println!("Browse to: {}", flow.get_auth_url());

    let token = flow.wait_for_token().await;

    //let stdin = io::stdin();
    //let input = &mut String::new();
    //println!("Enter code: ");
    //let _n = stdin.read_line(input).unwrap();
    //let code = input.clone();
    //let token = flow.exchange_code_for_token(code).await;

    dbg!(token);

    return Ok(());
}
