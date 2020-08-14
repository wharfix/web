
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
    RepositoryNotFound,
    RepositoryIsPrivate,
    RepositoryIsArchived,
    RepositoryIsDisabled,
    RepositoryIsTooBig,
}


impl Display for WharfixWebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            WharfixWebError::BadRequest => "Your browser sent a malformed request to the server.",
            WharfixWebError::SessionExpired => "Your session has expired, try logging in again.",
            WharfixWebError::RepositoryNotFound => "Repository not found.",
            WharfixWebError::RepositoryIsPrivate => "Repository is Private, it must be public.",
            WharfixWebError::RepositoryIsArchived => "Repository is Archived.",
            WharfixWebError::RepositoryIsDisabled => "Repository is Disabled.",
            WharfixWebError::RepositoryIsTooBig => "Repository is too big. For now it can't be bigger than 100 MB.",
        })
    }
}

impl std::convert::Into<actix_web::error::Error> for WharfixWebError {
    fn into(self) -> actix_web::error::Error {
        use actix_web::dev::HttpResponseBuilder;
        use actix_web::http::StatusCode;

        let target = match &self {
            WharfixWebError::SessionExpired => "/",
            _ => "/manage"
        };

        HttpResponseBuilder::new(StatusCode::FOUND)
            .header("location", format!("{target}?msg={msg}", target=target, msg=self.as_ref())).take().into()
    }
}
