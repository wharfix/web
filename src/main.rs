extern crate actix_web;
extern crate clap;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate lazy_static;
extern crate time;
extern crate tokio;
extern crate uuid;

use actix_web::http::StatusCode;
use std::collections::HashMap;
use std::string::String;

use actix_web::{App, HttpServer, HttpResponse, middleware, Responder, web};

use crate::actix_web::dev::Service;
use actix_web::dev::{HttpResponseBuilder};
use std::path::{PathBuf};
use std::fs;
use std::str::FromStr;

use crate::errors::{MainError, RepoError};
use actix_files as afs;


use oauth2::basic::BasicClient;

// Alternatively, this can be `oauth2::curl::http_client` or a custom client.
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};

use std::env;

mod errors;
mod exec;
mod log;

fn main() {

    let args = clap::App::new("wharfix")
    .arg(clap::Arg::with_name("address")
        .long("address")
        .help("Listen address to open on <port>")
        .default_value("0.0.0.0")
        .required(false))
    .arg(clap::Arg::with_name("port")
        .long("port")
        .help("Listen port to open on <address>")
        .default_value("8088")
        .required(true));

    if let Err(e) = || -> Result<(), MainError> {

        let m = args.get_matches();
        let listen_address = m.value_of("address").unwrap().to_string();
        let listen_port: u16 = m.value_of("port")
            .ok_or(MainError::ArgParse("Missing cmdline arg 'port'"))?.parse()
            .or(Err(MainError::ArgParse("cmdline arg 'port' doesn't look like a port number")))?;

        listen(listen_address, listen_port)
            .or_else(|e| Err(MainError::ListenBind(e)))

    }() {
        log::error("startup error", &e);
    }
}

#[actix_rt::main]
async fn listen(listen_address: String, listen_port: u16) -> std::io::Result<()>{
    log::info(&format!("start listening on port: {}", listen_port));

    HttpServer::new(|| {
        App::new()
            .wrap_fn(|req, srv| {
                log::new_request();
                log::data("request", &json!({ "endpoint": format!("{}", req.path()) }));
                srv.call(req)
            })
            .wrap(middleware::Compress::default())
            .route("/", web::get().to(frontpage))
            .route("/auth", web::get().to(github_auth))
            .route("/oauth/callback", web::get().to(github_callback))
            .service(afs::Files::new("/static", "static"))
            //.route("/static/{asset}", web::get().to(manifest))
            //.route("/signup", web::post().to(signup))
    })
        .bind(format!("{listen_address}:{listen_port}", listen_address=listen_address, listen_port=listen_port))?
        .run()
        .await
}


async fn frontpage() -> impl Responder {
    use askama::Template; // bring trait in scope
    use actix_web::{Error, HttpRequest, HttpResponse, Responder};
use serde::Serialize;
use futures::future::{ready, Ready};

    #[derive(Template)] // this will generate the code...
    #[template(path = "frontpage.html")] // using the template in this path, relative
                                     // to the `templates` dir in the crate root
    struct FrontPageTemplate<'a> { // the name of the struct can be anything
        name: &'a str, // the field name should match the variable name
                       // in your template
    }

    impl Responder for FrontPageTemplate<'_> {
    type Error = Error;
    type Future = Ready<Result<HttpResponse, Error>>;

    fn respond_to(self, _req: &HttpRequest) -> Self::Future {
        // Create response and set content type
        ready(Ok(HttpResponse::Ok()
            .content_type("text/html")
            .body(self.render().unwrap())))
    }

}

    let hello = FrontPageTemplate { name: "world" }; // instantiate your struct
    hello
}

async fn github_auth() -> impl Responder {
    let github_client_id = ClientId::new(
        env::var("GITHUB_CLIENT_ID").expect("Invalid client id")
    );

    let github_client_secret = ClientSecret::new(
        env::var("GITHUB_CLIENT_SECRET").expect("Invalid github client secret")
    );

    let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
        .expect("Invalid authorization endpoint URL");

    let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
        .expect("Invalid token endpoint URL");

    // Set up the config for the Github OAuth2 process.
    let client = BasicClient::new(
        github_client_id,
        Some(github_client_secret),
        auth_url,
        Some(token_url),
    )
    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_url(
        RedirectUrl::new("https://wharfix.dev/oauth/callback".to_string()).expect("Invalid redirect URL"),
    );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the user's public repos and email.
        .add_scope(Scope::new("user:email".to_string()))
        .url();

    HttpResponse::Found()
                       .header("location", authorize_url.to_string())
                       .finish()
}


#[derive(Deserialize, Debug)]
struct GithubCallback {
    access_token: String,
    expires_in: u64,
    refresh_token: String,
    refresh_token_expires_in: u64,
    scope: String,
    token_type: String,
}

async fn github_callback<'l>(callback: web::Path<GithubCallback>) -> impl Responder {
    HttpResponse::Ok()
                       .finish()
}
