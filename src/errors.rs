
use std::boxed::Box;
use crate::exec::ExecErrorInfo;
use std::fmt::Display;
use actix_web::dev::HttpResponseBuilder;

use actix_web::{Error, HttpRequest, HttpResponse, Responder};
use futures::future::{ready, Ready};

extern crate strum;
extern crate strum_macros;

use strum_macros::{EnumString, AsRefStr};
use std::str::FromStr;

#[allow(dead_code)]
pub enum ImageBuildError {
    NotFound,
    Other
}

#[derive(Debug)]
pub enum MainError {
    ArgParse(&'static str),
    ListenBind(std::io::Error),
    RepoClone(RepoError)
}

#[derive(Debug)]
pub enum RepoError {
    Exec(ExecErrorInfo),
    IO(Box<dyn std::fmt::Debug>),
}

impl std::convert::From<ExecErrorInfo> for RepoError {
    fn from(err: ExecErrorInfo) -> Self {
        RepoError::Exec(err)
    }
}

#[derive(AsRefStr, EnumString, Debug)]
pub enum WharfixWebError {
    BadRequest,
    SessionExpired,
}

impl Display for WharfixWebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            BadRequest => "Your browser sent a malformed request to the server.",
            SessionExpired => "Your session has expired, try logging in again.",
        })
    }
}

impl std::convert::Into<actix_web::error::Error> for WharfixWebError {
    fn into(self) -> actix_web::error::Error {
        match self {
            WharfixWebError::BadRequest => actix_web::error::ErrorBadRequest(self),
            WharfixWebError::SessionExpired => actix_web::error::ErrorForbidden(self)
        }
    }
}
