use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::prelude::*;
use failure::Error;

#[derive(Clone)]
pub struct OAuthClientConfig {
    client_id: String,
    client_secret: String,
    well_known_url: reqwest::Url,
}

impl OAuthClientConfig {
    pub fn new(client_id: &str, client_secret: &str, well_known_url: &str) -> Result<Self, url::ParseError> {
        Ok(Self {
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
            well_known_url: reqwest::Url::parse(well_known_url)?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct OAuthWellKnown {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    jwks_uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthTokenIntrospectAccess {
    roles: Vec<String>
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthTokenIntrospect {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub sub: Option<String>,
    #[serde(default, deserialize_with = "de_aud")]
    pub aud: Option<Vec<String>>,
    pub iss: Option<String>,
    pub jti: Option<String>,
    pub realm_access: Option<OAuthTokenIntrospectAccess>,
    pub resource_access: Option<HashMap<String, OAuthTokenIntrospectAccess>>,
}

struct AudVisitor;

impl<'de> serde::de::Visitor<'de> for AudVisitor {
    type Value = Option<Vec<String>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a string or an array of strings")
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Some(vec![value.to_string()]))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut value: A) -> Result<Self::Value, A::Error>  {
        let mut values = vec![];
        while let Some(elm) = value.next_element::<&str>()? {
            values.push(elm.to_string());
        }
        Ok(Some(values))
    }
}

fn de_aud<'de, D: serde::Deserializer<'de>,>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    d.deserialize_any(AudVisitor)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuthIdToken {
    pub sub: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: Option<String>,
    refresh_expires_in: Option<i64>,
    id_token: Option<String>,
    scopes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<DateTime<Utc>>,
    pub id_token: Option<String>,
}

#[derive(Serialize)]
struct OAuthTokenGrantForm<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    grant_type: &'a str,
}

#[derive(Serialize)]
struct OAuthTokenRefreshGrantForm<'a> {
    #[serde(flatten)]
    grant: OAuthTokenGrantForm<'a>,
    refresh_token: &'a str,
}

#[derive(Serialize)]
struct OAuthTokenCodeGrantForm<'a> {
    #[serde(flatten)]
    grant: OAuthTokenGrantForm<'a>,
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<&'a str>,
}

#[derive(Serialize)]
struct OAuthTokenIntrospectForm<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    token: &'a str,
}

#[derive(Debug, Fail)]
pub enum VerifyTokenError {
    #[fail(display = "internal server error")]
    InternalServerError(String),
    #[fail(display = "forbidden")]
    Forbidden,
}

impl actix_web::error::ResponseError for VerifyTokenError {
    fn error_response(&self) -> actix_web::web::HttpResponse {
        match self {
            VerifyTokenError::InternalServerError(_) => actix_web::web::HttpResponse::new(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR),
            VerifyTokenError::Forbidden => actix_web::web::HttpResponse::new(actix_web::http::StatusCode::FORBIDDEN)
        }
    }
}

impl From<reqwest::Error> for VerifyTokenError {
    fn from(error: reqwest::Error) -> VerifyTokenError {
        VerifyTokenError::InternalServerError(format!("{}", error))
    }
}

impl From<failure::Error> for VerifyTokenError {
    fn from(error: failure::Error) -> VerifyTokenError {
        VerifyTokenError::InternalServerError(format!("{}", error))
    }
}

#[derive(Clone)]
pub struct OAuthClient {
    config: OAuthClientConfig,
    client: reqwest::Client,
    _well_known: Arc<RwLock<Option<OAuthWellKnown>>>,
    _access_token: Arc<RwLock<Option<OAuthToken>>>,
    _jwks: Arc<RwLock<Option<alcoholic_jwt::JWKS>>>,
}

impl OAuthClient {
    pub fn new(config: OAuthClientConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            _well_known: Arc::new(RwLock::new(None)),
            _access_token: Arc::new(RwLock::new(None)),
            _jwks: Arc::new(RwLock::new(None)),
        }
    }

    async fn well_known(&self) -> Result<OAuthWellKnown, Error> {
        if let Some(well_known) = self._well_known.read().unwrap().clone() {
            return Ok(well_known);
        }

        let c = crate::util::async_reqwest_to_error(
            self.client.get(self.config.well_known_url.clone())
        ).await?;
        let d = c.json::<OAuthWellKnown>().await?;
        *self._well_known.write().unwrap() = Some(d.clone());
        Ok(d)
    }

    async fn jwks(&self) -> Result<alcoholic_jwt::JWKS, Error> {
        if let Some(jwks) = self._jwks.read().unwrap().clone() {
            return Ok(jwks);
        }

        let w = self.well_known().await?;
        match w.jwks_uri {
            Some(u) => {
                let c = crate::util::async_reqwest_to_error(
                    self.client.get(&u)
                ).await?;
                let d = c.json::<alcoholic_jwt::JWKS>().await?;
                *self._jwks.write().unwrap() = Some(d.clone());
                Ok(d)
            }
            None => Err(failure::err_msg("no jwks uri"))
        }
    }

    pub async fn authorization_url(&self, scopes: &[&str], response_type: &str, state: Option<&str>, redirect_url: Option<&str>, additional: Option<&[(&str, &str)]>) -> Result<String, Error> {
        let well_known = self.well_known().await?;

        let scopes = scopes.join(" ");
        let response_type = response_type.to_string();

        let mut pairs = vec![
            ("client_id", self.config.client_id.clone()),
            ("scope", scopes),
            ("response_type", response_type),
        ];

        if let Some(ref redirect_url) = redirect_url {
            pairs.push(("redirect_uri", redirect_url.to_string()));
        }

        if let Some(ref state) = state {
            pairs.push(("state", state.to_string()));
        }

        let mut url = reqwest::Url::parse(&well_known.authorization_endpoint)?;

        url.query_pairs_mut().extend_pairs(
            pairs.iter().map(|(k, v)| { (k, &v[..]) })
        );
        if let Some(additional) = additional {
            url.query_pairs_mut().extend_pairs(
                additional.iter().map(|(k, v)| { (k, &v[..]) })
            );
        }

        Ok(url.to_string())
    }

    pub async fn logout_url(&self, id_token: Option<&str>, redirect_url: Option<&str>) -> Result<String, Error> {
        let well_known = self.well_known().await?;


        let mut pairs = vec![];

        if let Some(ref id_token) = id_token {
            pairs.push(("id_token_hint", id_token));
        }
        if let Some(ref redirect_url) = redirect_url {
            pairs.push(("post_logout_redirect_uri", redirect_url));
        }

        let mut url = match &well_known.end_session_endpoint {
            Some(u) => reqwest::Url::parse(u)?,
            None => return Err(failure::err_msg("no end session endpoint"))
        };

        url.query_pairs_mut().extend_pairs(
            pairs.iter().map(|(k, v)| { (k, &v[..]) })
        );

        Ok(url.to_string())
    }

    pub async fn token_exchange(&self, code: &str, redirect_url: Option<&str>) -> Result<OAuthToken, Error> {
        let w = self.well_known().await?;

        match w.token_endpoint {
            Some(u) => {
                let grant = OAuthTokenGrantForm {
                    client_id: &self.config.client_id,
                    client_secret: &self.config.client_secret,
                    grant_type: "authorization_code",
                };

                let form = OAuthTokenCodeGrantForm {
                    grant,
                    redirect_uri: redirect_url,
                    code,
                };

                let c = crate::util::async_reqwest_to_error(
                    self.client.post(&u)
                        .form(&form)
                ).await?;
                let t = c.json::<OAuthTokenResponse>().await?;

                let now = Utc::now();

                Ok(OAuthToken {
                    access_token: t.access_token.clone(),
                    expires_at: now + chrono::Duration::seconds(t.expires_in),
                    refresh_token: t.refresh_token.clone(),
                    refresh_expires_at: match t.refresh_expires_in {
                        Some(e) => Some(now + chrono::Duration::seconds(e)),
                        None => None
                    },
                    id_token: t.id_token.clone(),
                })
            }
            None => Err(failure::err_msg("no token endpoint"))
        }
    }

    pub async fn get_access_token(&self) -> Result<String, Error> {
        let now = Utc::now();

        let cached_token = {
            self._access_token.read().unwrap().clone()
        };
        if let Some(access_token) = cached_token {
            if access_token.expires_at > now {
                return Ok(access_token.access_token);
            } else if let Some(refresh_expires_at) = access_token.refresh_expires_at {
                if let Some(refresh_token) = access_token.refresh_token {
                    if refresh_expires_at > now {
                        let w = self.well_known().await?;
                        return match w.token_endpoint {
                            Some(u) => {
                                let grant = OAuthTokenGrantForm {
                                    client_id: &self.config.client_id,
                                    client_secret: &self.config.client_secret,
                                    grant_type: "refresh_token",
                                };

                                let form = OAuthTokenRefreshGrantForm {
                                    grant,
                                    refresh_token: &refresh_token,
                                };

                                let c = crate::util::async_reqwest_to_error(
                                    self.client.post(&u).form(&form)
                                ).await?;
                                let t = c.json::<OAuthTokenResponse>().await?;
                                *self._access_token.write().unwrap() = Some(OAuthToken {
                                    access_token: t.access_token.clone(),
                                    expires_at: now + chrono::Duration::seconds(t.expires_in),
                                    refresh_token: t.refresh_token.clone(),
                                    refresh_expires_at: match t.refresh_expires_in {
                                        Some(e) => Some(now + chrono::Duration::seconds(e)),
                                        None => None
                                    },
                                    id_token: None,
                                });
                                Ok(t.access_token)
                            }
                            None => Err(failure::err_msg("no token endpoint"))
                        };
                    }
                }
            }
        }

        let w = self.well_known().await?;
        match w.token_endpoint {
            Some(u) => {
                let form = OAuthTokenGrantForm {
                    client_id: &self.config.client_id,
                    client_secret: &self.config.client_secret,
                    grant_type: "client_credentials",
                };

                let c = crate::util::async_reqwest_to_error(
                    self.client.post(&u).form(&form)
                ).await?;
                let t = match c.json::<OAuthTokenResponse>().await {
                    Ok(c) => c,
                    Err(e) => return Err(e.into())
                };
                *self._access_token.write().unwrap() = Some(OAuthToken {
                    access_token: t.access_token.clone(),
                    expires_at: now + chrono::Duration::seconds(t.expires_in),
                    refresh_token: t.refresh_token.clone(),
                    refresh_expires_at: match t.refresh_expires_in {
                        Some(e) => Some(now + chrono::Duration::seconds(e)),
                        None => None
                    },
                    id_token: None,
                });
                Ok(t.access_token)
            }
            None => Err(failure::err_msg("no token endpoint"))
        }
    }

    pub async fn introspect_token(&self, token: &str) -> Result<OAuthTokenIntrospect, Error> {
        let w = self.well_known().await?;
        match w.introspection_endpoint {
            Some(u) => {
                let form = OAuthTokenIntrospectForm {
                    client_id: &self.config.client_id,
                    client_secret: &self.config.client_secret,
                    token,
                };

                let c = crate::util::async_reqwest_to_error(
                    self.client.post(&u).form(&form)
                ).await?;

                let i = c.json::<OAuthTokenIntrospect>().await?;
                debug!("Introspected token to be: {:?}", i);
                Ok(i)
            }
            None => Err(failure::err_msg("no introspection endpoint"))
        }
    }

    pub async fn verify_token<'a, R>(&self, token: &str, role: R) -> Result<OAuthTokenIntrospect, VerifyTokenError>
        where R: Into<Option<&'a str>>
    {
        let i = self.introspect_token(token).await?;

        if !i.active {
            return Err(VerifyTokenError::Forbidden);
        }

        if let Some(r) = role.into() {
            match (&i.aud, &i.resource_access) {
                (Some(aud), Some(resource_access)) => {
                    if !aud.contains(&self.config.client_id) ||
                        !resource_access.contains_key(&self.config.client_id) ||
                        !resource_access.get(&self.config.client_id).unwrap().roles.contains(&r.to_owned()) {
                        return Err(VerifyTokenError::Forbidden);
                    }
                    Ok(i)
                }
                _ => Err(VerifyTokenError::Forbidden)
            }
        } else {
            Ok(i)
        }
    }

    pub async fn update_and_verify_token<'a, R>(&self, token: OAuthToken, role: R) -> Result<(OAuthTokenIntrospect, OAuthToken), VerifyTokenError>
        where R: Into<Option<&'a str>>
    {
        let now = Utc::now();

        let access_token = {
            if token.expires_at > now {
                token
            } else if let Some(refresh_expires_at) = token.refresh_expires_at {
                if let Some(refresh_token) = &token.refresh_token {
                    if refresh_expires_at > now {
                        let w = self.well_known().await?;
                        match w.token_endpoint {
                            Some(u) => {
                                let grant = OAuthTokenGrantForm {
                                    client_id: &self.config.client_id,
                                    client_secret: &self.config.client_secret,
                                    grant_type: "refresh_token",
                                };

                                let form = OAuthTokenRefreshGrantForm {
                                    grant,
                                    refresh_token: &refresh_token,
                                };

                                let c = crate::util::async_reqwest_to_error(
                                    self.client.post(&u).form(&form)
                                ).await?;
                                let t = c.json::<OAuthTokenResponse>().await?;

                                OAuthToken {
                                    access_token: t.access_token.clone(),
                                    expires_at: now + chrono::Duration::seconds(t.expires_in),
                                    refresh_token: t.refresh_token.clone(),
                                    refresh_expires_at: match t.refresh_expires_in {
                                        Some(e) => Some(now + chrono::Duration::seconds(e)),
                                        None => None
                                    },
                                    id_token: None,
                                }
                            }
                            None => return Err(VerifyTokenError::InternalServerError("no token endpoint".to_string()))
                        }
                    } else {
                        return Err(VerifyTokenError::Forbidden);
                    }
                } else {
                    return Err(VerifyTokenError::Forbidden);
                }
            } else {
                return Err(VerifyTokenError::Forbidden);
            }
        };

        let introspect = self.verify_token(&access_token.access_token, role).await?;

        Ok((introspect, access_token.to_owned()))
    }

    pub async fn verify_id_token(&self, token: &str) -> Result<OAuthIdToken, Error> {
        let keys = self.jwks().await?;

        let validations = vec![
            alcoholic_jwt::Validation::Audience(self.config.client_id.clone()),
            alcoholic_jwt::Validation::NotExpired,
            alcoholic_jwt::Validation::SubjectPresent,
        ];

        let kid = match match alcoholic_jwt::token_kid(token) {
            Ok(k) => k,
            Err(e) => return Err(failure::err_msg(format!("{:?}", e)))
        } {
            Some(k) => k,
            None => return Err(failure::err_msg("no token kid"))
        };

        let key = match keys.find(&kid) {
            Some(k) => k,
            None => return Err(failure::err_msg("unable to find key"))
        };

        let token = match alcoholic_jwt::validate(token, key, validations) {
            Ok(k) => k,
            Err(e) => return Err(failure::err_msg(format!("{:?}", e)))
        };

        match serde_json::from_value(token.claims) {
            Ok(c) => Ok(c),
            Err(e) => Err(e.into())
        }
    }
}

#[derive(Debug)]
pub struct BearerAuthToken {
    token: String
}

impl BearerAuthToken {
    pub fn token(&self) -> &str {
        &self.token
    }
}

#[derive(Debug)]
pub struct OptionalBearerAuthToken {
    token: Option<String>
}

impl OptionalBearerAuthToken {
    pub fn token(&self) -> Option<&str> {
        match &self.token {
            Some(t) => Some(&t),
            None => None
        }
    }
}

impl actix_web::FromRequest for BearerAuthToken {
    type Error = actix_web::Error;
    type Future = Result<Self, Self::Error>;
    type Config = ();

    fn from_request(req: &actix_web::HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let auth_header = req.headers().get(actix_web::http::header::AUTHORIZATION);
        if let Some(auth_token) = auth_header {
            if let Ok(auth_token_str) = auth_token.to_str() {
                let auth_token_str = auth_token_str.trim();
                if auth_token_str.starts_with("Bearer ") {
                    Ok(Self {
                        token: auth_token_str[7..].to_owned()
                    })
                } else {
                    Err(actix_web::HttpResponse::new(http::StatusCode::UNAUTHORIZED).into())
                }
            } else {
                Err(actix_web::HttpResponse::new(http::StatusCode::UNAUTHORIZED).into())
            }
        } else {
            Err(actix_web::HttpResponse::new(http::StatusCode::UNAUTHORIZED).into())
        }
    }
}

impl actix_web::FromRequest for OptionalBearerAuthToken {
    type Error = actix_web::Error;
    type Future = Result<Self, Self::Error>;
    type Config = ();

    fn from_request(req: &actix_web::HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let auth_header = req.headers().get(actix_web::http::header::AUTHORIZATION);
        if let Some(auth_token) = auth_header {
            if let Ok(auth_token_str) = auth_token.to_str() {
                let auth_token_str = auth_token_str.trim();
                if auth_token_str.starts_with("Bearer ") {
                    Ok(Self {
                        token: Some(auth_token_str[7..].to_owned())
                    })
                } else {
                    Ok(Self {
                        token: None
                    })
                }
            } else {
                Ok(Self {
                    token: None
                })
            }
        } else {
            Ok(Self {
                token: None
            })
        }
    }
}
