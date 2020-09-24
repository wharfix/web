extern crate actix_web;
extern crate clap;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate lazy_static;
extern crate time;
extern crate tokio;
extern crate uuid;
extern crate rand;
extern crate regex;

use rand::{Rng};

use actix_web::http::StatusCode;
use std::collections::HashMap;
use std::string::String;

use actix_web::{App, Error, HttpServer, HttpRequest, HttpResponse, middleware, Responder, web};

use crate::actix_web::dev::Service;
use actix_web::dev::{HttpResponseBuilder};
use std::path::{Path, PathBuf};
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


use askama::Template; // bring trait in scope
use serde::Serialize;
use futures::future::{ready, Ready};
use std::fmt::Display;

use actix_session::{CookieSession, Session};

mod errors;
mod exec;
mod log;

use crate::errors::WharfixWebError;

enum WharfixWebResponse {
    Template(Box<dyn Template>),
    Redirect(String)
}

impl WharfixWebResponse {
    fn wrap<T: 'static>(content: T) -> Self where T: Template {
        WharfixWebResponse::Template(Box::new(BaseTemplate { content }))
    }

    fn redirect(target: &str) -> Self {
        WharfixWebResponse::Redirect(target.to_string())
    }
}

#[derive(Template)]
#[template(path = "base.html", escape = "none")]
struct BaseTemplate<T> where T: Template {
  content: T
}

//struct WharfixWebResult(Result<WharfixWebResponse, WharfixWebError>);
type WharfixWebResult = Result<WharfixWebResponse, WharfixWebError>;

impl Responder for WharfixWebResponse {
    type Error = Error;
    type Future = Ready<Result<HttpResponse, Error>>;

    fn respond_to(self, _req: &HttpRequest) -> Self::Future {
        ready(Ok(match self {
            WharfixWebResponse::Template(t) => HttpResponse::Ok()
                        .content_type("text/html")
                        .body(t.render().unwrap()),
            WharfixWebResponse::Redirect(target) => HttpResponse::Found()
                        .header("location", target).finish(),
            //Err(e) => HttpResponse::Found()
            //            .header("location", format!("/?msg={}", e.as_ref()))
        }))
    }
}

struct Config {
    listen_address: String,
    listen_port: u16,
    domain: String,
    webroot: PathBuf,
    db_conn_string: String,
    github_client_id: String,
    github_client_secret: String,
    user_whitelist: Vec<String>,
}

impl Config {
    pub fn get() -> &'static Config {
        unsafe {
            CONFIG.as_ref().unwrap()
        }
    }
    fn set(config: Config) {
        unsafe {
            CONFIG = Some(config);
        }
    }
}

static mut CONFIG: Option<Config> = None;

fn main() {

    let args = clap::App::new("wharfix")
    .arg(clap::Arg::with_name("address")
        .long("address")
        .help("Listen address to open on <port>")
        .takes_value(true)
        .default_value("0.0.0.0")
        .required(false))
    .arg(clap::Arg::with_name("port")
        .long("port")
        .help("Listen port to open on <address>")
        .takes_value(true)
        .default_value("8088")
        .required(true))
    .arg(clap::Arg::with_name("domain")
        .long("domain")
        .help("Domain at which the application is serving")
        .takes_value(true)
        .default_value("localhost")
        .required(false))
    .arg(clap::Arg::with_name("webroot")
        .long("webroot")
        .help("Path to webroot directory")
        .takes_value(true)
        .default_value("webroot")
        .required(false))
    .arg(clap::Arg::with_name("db-conn-file")
        .long("db-conn-file")
        .help("Path to file containing db connection details")
        .takes_value(true)
        .required(true))
    .arg(clap::Arg::with_name("github-client-id")
        .long("github-client-id")
        .help("Github client ID")
        .takes_value(true)
        .required(true))
    .arg(clap::Arg::with_name("github-client-secret-file")
        .long("github-client-secret-file")
        .help("Path to file containing github client secret")
        .takes_value(true)
        .required(true))
    .arg(clap::Arg::with_name("user-whitelist")
        .long("user-whitelist")
        .help("User whitelist (comma separated)")
        .takes_value(true)
        .required(true));

    if let Err(e) = || -> Result<(), MainError> {

        let m = args.get_matches();
        let listen_address = m.value_of("address").unwrap().to_string();
        let listen_port: u16 = m.value_of("port")
            .ok_or(MainError::ArgParse("Missing cmdline arg 'port'"))?.parse()
            .or(Err(MainError::ArgParse("cmdline arg 'port' doesn't look like a port number")))?;

        let domain = m.value_of("domain").unwrap().to_string();
        let webroot = PathBuf::from(m.value_of("webroot").unwrap());
        let db_conn_string = fs::read_to_string(&PathBuf::from(m.value_of("db-conn-file").unwrap())).expect("unable to read db-conn-file");

        let github_client_id = m.value_of("github-client-id").unwrap().to_string();
        let github_client_secret = fs::read_to_string(&PathBuf::from(m.value_of("github-client-secret-file").unwrap())).and_then(|s| Ok(s.trim().to_string())).unwrap();

        let user_whitelist = m.value_of("user-whitelist").unwrap().to_string();
        let user_whitelist: Vec<String> = user_whitelist.split(',').map(|s| s.to_string()).collect();

        let config = Config{
            listen_address,
            listen_port,
            domain,
            webroot,
            db_conn_string,
            github_client_id,
            github_client_secret,
            user_whitelist,
        };
        unsafe {
            Config::set(config);
        }

        listen()
            .or_else(|e| Err(MainError::ListenBind(e)))

    }() {
        log::error("startup error", &e);
    }
}

#[actix_rt::main]
async fn listen() -> std::io::Result<()>{
    use actix_session::CookieSession;

    let config = Config::get();
    let listen_address = &config.listen_address;
    let listen_port = &config.listen_port;
    let domain = &config.domain;
    let webroot = &config.webroot;

    log::info(&format!("start listening on port: {}", listen_port));

    HttpServer::new(move || {
        App::new()
            .wrap_fn(|req, srv| {
                log::new_request();
                log::data("request", &json!({ "endpoint": format!("{}", req.path()) }));
                srv.call(req)
            })
        .wrap(middleware::Compress::default())
            .wrap(CookieSession::signed(&[0; 32])
              .domain(domain)
              .name("actix_session")
              .path("/")
              .secure(false))
            .route("/", web::get().to(front_page))
            .route("/manage", web::get().to(manage_page))
            .route("/manage", web::post().to(repo_submit))
            .route("/auth", web::get().to(github_auth))
            .route("/oauth/callback", web::get().to(github_callback))
            .service(afs::Files::new("/res", webroot.join("res")))
    })
        .bind(format!("{listen_address}:{listen_port}", listen_address=listen_address, listen_port=listen_port))?
        .run()
        .await
}

#[derive(Debug, Serialize, Deserialize)]
struct FeedbackInfo {
    msg: Option<String>
}

async fn front_page(info: web::Query<FeedbackInfo>) -> WharfixWebResult {

    #[derive(Template)]
    #[template(path = "frontpage.html")]
    struct FrontPageTemplate {
        msg: Option<String>
    }

    let msg = info.msg.as_ref().and_then(|m| WharfixWebError::from_str(m).ok()).and_then(|m| Some(format!("{}", m.to_string())));

    Ok(WharfixWebResponse::wrap(FrontPageTemplate {
        msg
    }))
}

#[derive(Debug, Serialize, Deserialize)]
struct RepoParams {
    registry_name: String,
    registry_repourl: String,
    registry_enabled: Option<bool>
}

const REGISTRY_NAME_PATTERN: &str = r"^[a-z0-9][a-z0-9-]{3,63}$";
const REGISTRY_REPOURL_PATTERN: &str = r"^(https://)?github\.com/([a-zA-Z0-9-]{1,64})/([a-zA-Z0-9-]{1,64})/?(\.git)?$";

async fn repo_submit(session: Session, params: web::Form<RepoParams>) -> WharfixWebResult {
    use mysql::TxOpts;
    use regex::Regex;

    lazy_static! {
        static ref REGISTRY_NAME_RE: Regex = Regex::new(REGISTRY_NAME_PATTERN).unwrap();
        static ref REGISTRY_REPOURL_RE: Regex = Regex::new(REGISTRY_REPOURL_PATTERN).unwrap();
    }

    // -- server side form validation
    let bad_request = |message| {
        log::info(&format!("repo validation error: {}", &message));
        WharfixWebError::BadRequest
    };

    if !REGISTRY_NAME_RE.is_match(&params.registry_name) {
        return Err(bad_request("failed validation of registry name"))
    }

    let caps = REGISTRY_REPOURL_RE.captures(&params.registry_repourl).ok_or(bad_request("failed validation of repourl"))?;

    let organization = caps.iter().nth(2).and_then(|m| Some(m.unwrap().as_str())).ok_or(bad_request("failed to capture organization from repourl"))?;
    let repository = caps.iter().nth(3).and_then(|m| Some(m.unwrap().as_str())).ok_or(bad_request("failed to capture repository from repourl"))?;
    // -------------------------------------


    log::info(&format!("org: {}, rep: {}", organization, repository));

   let (userid, session_key) = touch_session(&session)?;


   /* Check repo */

    #[derive(Debug, Serialize, Deserialize)]
    struct GithubRepo {
        private: bool,
        archived: bool,
        disabled: bool,
        clone_url: String,
        size: u64,
    }

    let client = reqwest::Client::new();
    let repo: GithubRepo = client.get(&format!("https://api.github.com/repos/{organization}/{repository}", organization=organization, repository=repository))
        .header("User-Agent", "Wharfix-Web v0.1")
        .send()
        .await.or(Err(WharfixWebError::RepositoryNotFound))?
        .json()
        .await.or(Err(WharfixWebError::RepositoryNotFound))?;

    let repo_validation = {
        if repo.private {
           Err(WharfixWebError::RepositoryIsPrivate)
        }
        else if repo.archived {
           Err(WharfixWebError::RepositoryIsArchived)
        }
        else if repo.disabled {
           Err(WharfixWebError::RepositoryIsDisabled)
        }
        else if repo.size > 100*1024 {
           Err(WharfixWebError::RepositoryIsTooBig)
        }
        else {
           Ok(())
        }
    }?;
   // ***

    let mut conn = POOL.get_conn().unwrap();

    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    let res = tx.exec_iter("UPDATE registry SET repourl = :repourl, enabled = :enabled, modified = NOW() WHERE name = :name AND userid = :userid AND destroyed IS NULL", params! { "name" => &params.registry_name, "repourl" => &repo.clone_url, "enabled" => params.registry_enabled.unwrap_or_default(), userid });

    if res.unwrap().affected_rows() == 0 {
        tx.exec_drop("UPDATE registry SET destroyed = NOW() WHERE userid = :userid AND destroyed IS NULL", params! { userid }).unwrap();
        tx.exec_drop("INSERT INTO registry (userid, name, repourl, enabled, created) VALUES (:userid, :name, :repourl, :enabled, NOW())", params! { userid, "name" => &params.registry_name, "repourl" => &repo.clone_url, "enabled" => params.registry_enabled.unwrap_or_default() }).unwrap();
    }
    tx.commit().unwrap();

    Ok(WharfixWebResponse::redirect("/manage"))
}

fn touch_session(session: &Session) -> Result<(u64, String), WharfixWebError> {
    use mysql::TxOpts;

    let session_key = session.get::<String>("key").unwrap().unwrap();

    let mut conn = POOL.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();

    let (userid, session_key) = tx.exec_first("SELECT userid, sessionkey FROM session WHERE sessionkey = :session_key AND expiry > NOW() FOR UPDATE", params! { "session_key" => &session_key }).unwrap().ok_or(WharfixWebError::SessionExpired)?;
    tx.exec_drop("UPDATE session SET expiry = ADDTIME(expiry, 30 * 60) WHERE sessionkey = :session_key AND userid = :userid", params! { "session_key" => &session_key, userid }).unwrap();

    tx.commit().unwrap();

    Ok((userid, session_key))
}

async fn manage_page(session: Session, info: web::Query<FeedbackInfo>) -> WharfixWebResult {

   #[derive(Template)]
   #[template(path = "managepage.html")]
   struct ManagePageTemplate {
     login: String,
     name: String,
     name_pattern: String,
     repourl: String,
     repourl_pattern: String,
     enabled: bool,
     feedback_message: Option<String>,
     info_type: String,
     info_message: String,
   }

   impl Default for ManagePageTemplate {
       fn default() -> Self {
           Self {
                login: String::new(),
                name: String::new(),
                repourl: String::new(),
                enabled: false,
                feedback_message: None,
                info_type: String::new(),
                info_message: String::new(),
                name_pattern: REGISTRY_NAME_PATTERN.to_string(),
                repourl_pattern: REGISTRY_REPOURL_PATTERN.to_string(),
           }
       }
   }

   let (_, session_key) = touch_session(&session)?;

   let mut conn = POOL.get_conn().unwrap();
   let row: Option<(_, _, _, _)> = conn.exec_first("SELECT U.login, R.name, R.repourl, R.enabled FROM user U INNER JOIN session S ON S.userid = U.id LEFT JOIN registry R ON R.userid = S.userid AND R.destroyed IS NULL WHERE S.sessionkey = :session_key AND S.expiry > NOW()", params! { session_key }).unwrap();

   let content: ManagePageTemplate = row.and_then(|(login, name, repourl, enabled): (String, Option<String>, Option<String>, Option<bool>)| {
        let enabled = enabled.unwrap_or_default();
        let info_type = (if enabled { "success" } else { "info" }).to_string();
        let info_message = (if enabled { "Registry is online and serving requests." } else { "Registry is inactive." }).to_string();
        let feedback_message = info.msg.as_ref().and_then(|msg| WharfixWebError::from_str(&msg).ok().and_then(|m| Some(m.to_string())));

        Some(ManagePageTemplate {
            login,
            name: name.unwrap_or_default(),
            repourl: repourl.unwrap_or_default(),
            enabled,
            feedback_message,
            info_type,
            info_message,
            ..Default::default()
        })
   }).unwrap_or_default();

   Ok(WharfixWebResponse::wrap(content))
}

async fn github_auth(mut session: Session) -> impl Responder {

    let state = init_db_session(&mut session);
    let config = Config::get();

    let github_client_id = ClientId::new(config.github_client_id.clone());
    let github_client_secret = ClientSecret::new(config.github_client_secret.clone());

    let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
        .expect("Invalid authorization endpoint URL");

    let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
        .expect("Invalid token endpoint URL");

    let domain = match config.domain.as_str() {
        "localhost" => "http://localhost".to_string(),
        d => format!("https://{}", d)
    };

    // Set up the config for the Github OAuth2 process.
    let client = BasicClient::new(
        github_client_id,
        Some(github_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_url(
        RedirectUrl::new(format!("{}", &domain)).expect("Invalid redirect URL"),
    );

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(|| state.clone())
        // This example is requesting access to the user's public repos and email.
        .add_scope(Scope::new("user:email".to_string()))
        .url();

    HttpResponse::Found()
                       .header("location", authorize_url.to_string())
                       .finish()
}

#[macro_use] extern crate mysql;

use mysql::{FromRowError,Pool,Row};
use mysql::prelude::FromRow;
use crate::mysql::prelude::Queryable;

lazy_static! {
   static ref POOL: Pool = db_connect();
}

fn db_connect() -> Pool {
   let config = Config::get();
   Pool::new(&config.db_conn_string).unwrap()
}
const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

fn init_db_session(session: &mut Session) -> CsrfToken {
    use rand::distributions::Alphanumeric;
    use time::Duration;

    let sessionkey: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .collect();

    let csrf_token = CsrfToken::new_random();

    let state = csrf_token.secret(); 

    session.set("key", &sessionkey);

    let expiry = time::strftime(TIME_FORMAT, &(time::now_utc() + Duration::minutes(30))).unwrap();

    let mut conn = POOL.get_conn().unwrap(); //or(Err(ErrorInternalServerError("data connection error"))).unwrap();
    conn.exec_drop("INSERT INTO session (sessionkey, state, expiry) VALUES (:sessionkey, :state, :expiry)", params! { sessionkey, state, expiry }).unwrap(); 
    //.or(Err(ErrorInternalServerError("data query error"))).unwrap();
   
    csrf_token
}


#[derive(Deserialize, Debug)]
struct GithubCallback {
    access_token: String,
    token_type: String,
}

#[derive(Deserialize, Debug)]
struct GithubHandshake {
    code: String,
    state: String
}

#[derive(Deserialize, Debug)]
struct GithubUser {
    id: u64,
    login: String,
    name: String,
    email: String
}

async fn github_callback<'l>(handshake: web::Query<GithubHandshake>, session: Session) -> impl Responder {
    use mysql::TxOpts;
    use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};

    let now = time::strftime(TIME_FORMAT, &time::now_utc()).unwrap();
    let state = &handshake.state;

    // Remove after P1
    let config = Config::get();
    let user_whitelist = &config.user_whitelist;

    let mut conn = POOL.get_conn().unwrap();
    let res = conn.exec_first("SELECT sessionkey FROM session WHERE state = :state AND expiry > :now", params! { state, now }).unwrap(); 
    let (session_key) = res.unwrap();
    
    if session.get::<String>("key").unwrap() != session_key {
        panic!("session keys does not match");
    }

    // https://github.com/login/oauth/access_token
    // access_token=e72e16c7e42f292c6912e7710c838347ae178b4a&token_type=bearer
    
    /*
        client_id string Required. The client ID you received from GitHub for your GitHub App.
        client_secret string Required. The client secret you received from GitHub for your GitHub App.
        code string Required. The code you received as a response to Step 1.
        redirect_uri string The URL in your application where users are sent after authorization.
        state string The unguessable random string you provided in Step 1.
    */

    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();

    let config = Config::get();

    let github_client_id = &config.github_client_id;
    let github_client_secret = &config.github_client_secret;

    let params = [("client_id", github_client_id), ("client_secret", github_client_secret), ("code", &handshake.code), ("state", &handshake.state)];
    let client = reqwest::Client::new();
    let res = client.post("https://github.com/login/oauth/access_token")
        .form(&params)
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, "Wharfix Web")
        .send()
        .await.unwrap();

    let callback: GithubCallback = res.json().await.unwrap();
    
    let client = reqwest::Client::new();
    let res = client.get("https://api.github.com/user")
        .header(AUTHORIZATION, &format!("token {}", &callback.access_token))
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, "Wharfix Web")
        .send()
        .await.unwrap();

    //println!("{:?}", res.text().await.unwrap());

    let user: GithubUser = res.json().await.unwrap();

    let githubid = user.id;
    let login = user.login;
    let name = user.name;
    let email = user.email;
    let token = callback.access_token.clone();
    let created = time::strftime(TIME_FORMAT, &time::now_utc()).unwrap();
    let updated = created.clone();

    // Remove after P1
    user_whitelist.iter().find(|pred| pred.to_string() == login).expect(format!("user: {} not whitelistsed", &login).as_str());

    let existing_user: Option<u64> = tx.exec_first("SELECT id FROM user WHERE githubid = :githubid", params! { githubid }).unwrap();
    let user_id = match existing_user {
        Some(id) => {
            tx.exec_drop("UPDATE user SET login = :login, name = :name, email = :email, token = :token, updated = :updated WHERE id = :id", params! { login, name, email, token, updated, id }).unwrap();
            id
        },
        None => {
            let mut res = tx.exec_iter("INSERT INTO user (githubid, login, name, email, token, created, updated) VALUES (:githubid, :login, :name, :email, :token, :created, :updated)", params! { githubid, login, name, email, token, created, updated }).unwrap();
            let set = res.next_set().unwrap();
            let lol = set.unwrap();
            lol.last_insert_id().unwrap()
        }
    };

    tx.exec_drop("UPDATE session SET userid = :user_id WHERE sessionkey = :session_key", params! { user_id, session_key }).unwrap();

    tx.commit().unwrap();

    HttpResponse::Found()
                       .header("location", "/manage")
                       .finish()
}
