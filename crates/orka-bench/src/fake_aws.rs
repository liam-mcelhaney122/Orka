//! Fake AWS STS and IAM Identity Center (SSO) servers for tests.
//!
//! [`FakeSts`] answers the `AssumeRole` call the S3 backend makes for a
//! `role_arn` profile. [`FakeSsoPortal`] answers the federation call the
//! backend makes for an SSO profile. Neither server verifies a SigV4
//! signature in full: a real signature check needs the caller's secret
//! key, which the SSO and role-assumption paths intentionally hide from
//! each other. Each server instead checks the shape a real client sends
//! — an `Authorization` header naming a credential, or a bearer token —
//! which is enough to prove the backend signed or authenticated the
//! call at all.

use crate::fake_http::{Handler, Request, Response, Server};
use std::sync::Arc;

/// One set of temporary credentials a fake issues. The access key and
/// secret key must match whatever the S3 server under test expects, so
/// the credentials this fake hands back actually work on the wire.
#[derive(Clone)]
pub struct IssuedKeys {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: String,
}

/// A fake STS server that answers `Action=AssumeRole`.
///
/// Started once per test binary, since the S3 backend reads the STS
/// endpoint from the process-wide `ORKA_ENDPOINT_STS` variable.
pub struct FakeSts {
    server: Server,
}

impl FakeSts {
    /// Starts the server on an OS-assigned loopback port. Every
    /// `AssumeRole` call for `expected_role_arn` gets back `keys`; a
    /// call for any other role, or with no `Authorization` header at
    /// all, gets a `403`.
    pub fn start(expected_role_arn: impl Into<String>, keys: IssuedKeys) -> FakeSts {
        let expected_role_arn = expected_role_arn.into();
        let handler: Handler = Arc::new(move |req: &Request| route(req, &expected_role_arn, &keys));
        FakeSts {
            server: Server::start(handler),
        }
    }

    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// Every request this fake has received, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.server.requests()
    }
}

fn route(req: &Request, expected_role_arn: &str, keys: &IssuedKeys) -> Response {
    // A real STS call carries every parameter in the query string: the
    // S3 backend signs `AssumeRole` as a GET, not a POST, so this fake
    // only needs to look at `req.query`.
    let action = req.query_param("Action").unwrap_or("");
    if action != "AssumeRole" {
        return error_response(400, "InvalidAction", "Action must be AssumeRole");
    }
    // Full SigV4 verification needs the caller's secret key, which
    // this fake never sees; checking that a `Credential=` clause is
    // present is enough to prove the backend actually signed the
    // request rather than sending it bare.
    let Some(auth) = req.header("authorization") else {
        return error_response(403, "MissingAuthenticationToken", "no Authorization header");
    };
    if !auth.contains("Credential=") {
        return error_response(
            403,
            "InvalidClientTokenId",
            "Authorization header is malformed",
        );
    }
    let role_arn = req.query_param("RoleArn").unwrap_or("");
    if role_arn != expected_role_arn {
        return error_response(403, "AccessDenied", "RoleArn does not match");
    }
    Response::bytes(200, "text/xml", assume_role_response_xml(keys).into_bytes())
}

fn assume_role_response_xml(keys: &IssuedKeys) -> String {
    format!(
        "<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
           <AssumeRoleResult>\
             <Credentials>\
               <AccessKeyId>{}</AccessKeyId>\
               <SecretAccessKey>{}</SecretAccessKey>\
               <SessionToken>{}</SessionToken>\
               <Expiration>2999-01-01T00:00:00Z</Expiration>\
             </Credentials>\
           </AssumeRoleResult>\
         </AssumeRoleResponse>",
        keys.access_key, keys.secret_key, keys.session_token
    )
}

/// A fake IAM Identity Center (SSO) portal that answers
/// `GET /federation/credentials`.
///
/// Started once per test binary, since the S3 backend reads the portal
/// endpoint from the process-wide `ORKA_ENDPOINT_SSO_PORTAL` variable.
pub struct FakeSsoPortal {
    server: Server,
}

impl FakeSsoPortal {
    /// Starts the server on an OS-assigned loopback port. A call
    /// carrying `x-amz-sso_bearer_token: {expected_bearer_token}` gets
    /// back `keys`; any other bearer token gets a `401`.
    pub fn start(expected_bearer_token: impl Into<String>, keys: IssuedKeys) -> FakeSsoPortal {
        let expected_bearer_token = expected_bearer_token.into();
        let handler: Handler =
            Arc::new(move |req: &Request| sso_route(req, &expected_bearer_token, &keys));
        FakeSsoPortal {
            server: Server::start(handler),
        }
    }

    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// Every request this fake has received, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.server.requests()
    }
}

fn sso_route(req: &Request, expected_bearer_token: &str, keys: &IssuedKeys) -> Response {
    if req.path != "/federation/credentials" {
        return Response::text(404, "not found");
    }
    let bearer = req.header("x-amz-sso_bearer_token").unwrap_or("");
    if bearer != expected_bearer_token {
        return error_response(401, "UnauthorizedException", "bearer token does not match");
    }
    if req.query_param("account_id").is_none() || req.query_param("role_name").is_none() {
        return error_response(
            400,
            "InvalidRequestException",
            "account_id and role_name are required",
        );
    }
    Response::json(
        200,
        &serde_json::json!({
            "roleCredentials": {
                "accessKeyId": keys.access_key,
                "secretAccessKey": keys.secret_key,
                "sessionToken": keys.session_token,
                "expiration": 32_503_680_000_000i64,
            }
        }),
    )
}

/// An AWS-shaped JSON error body. The backend folds this text into its
/// own error message through `ureq::Error::Status`, so the exact shape
/// only needs to look plausible in a test failure message; no backend
/// code path parses it as structured data.
fn error_response(status: u16, code: &str, message: &str) -> Response {
    Response::json(
        status,
        &serde_json::json!({"Error": {"Code": code, "Message": message}}),
    )
}
