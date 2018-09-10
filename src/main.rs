extern crate base64;
extern crate oauth2;
extern crate rand;
extern crate url;

use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::{AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
             TokenUrl};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;

fn main() {
    let discord_client_id = ClientId::new(
        env::var("DISCORD_CLIENT_ID").expect("Missing the DISCORD_CLIENT_ID environment variable."),
    );
    let discord_client_secret = ClientSecret::new(
        env::var("DISCORD_CLIENT_SECRET")
            .expect("Missing the DISCORD_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new(
        Url::parse("https://discordapp.com/api/oauth2/authorize")
            .expect("Invalid authorization endpoint URL"),
    );
    let token_url = TokenUrl::new(
        Url::parse("https://discordapp.com/api/oauth2/token")
            .expect("Invalid token endpoint URL"),
    );

    // Set up the config for the discord OAuth2 process.
    let client = BasicClient::new(
            discord_client_id,
            Some(discord_client_secret),
            auth_url, Some(token_url)
        )
        // This example is requesting access to the user's public repos and email.
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("identity".to_string()))

        // This example will be running its own server at localhost:8080.
        // See below for the server implementation.
        .set_redirect_url(
            RedirectUrl::new(
                Url::parse("http://localhost:8080")
                    .expect("Invalid redirect URL")
            )
        );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client.authorize_url(CsrfToken::new_random);

    println!(
        "Open this URL in your browser:\n{}\n",
        authorize_url.to_string()
    );

    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url.query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url.query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            println!("Discord returned the following code:\n{}\n", code.secret());
            println!(
                "Discord returned the following state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token_res = client.exchange_code(code);

            println!("discord returned the following token:\n{:?}\n", token_res);

            if let Ok(token) = token_res {
                let scopes = if let Some(scopes_vec) = token.scopes() {
                    scopes_vec
                        .iter()
                        .map(|comma_separated| comma_separated.split(","))
                        .flat_map(|inner_scopes| inner_scopes)
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                println!("Discord returned the following scopes:\n{:?}\n", scopes);
            }

            // The server will terminate itself after collecting the first code.
            break;
        }
    }
}