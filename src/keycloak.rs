use rand::prelude::*;
use std::collections::HashMap;
use failure::Fallible;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub struct KeycloakClientConfig {
    base_url: reqwest::Url,
}

impl KeycloakClientConfig {
    pub fn new(base_url: &str, realm: &str) -> Result<Self, url::ParseError> {
        Ok(Self {
            base_url: reqwest::Url::parse(base_url)?.join(&format!("admin/realms/{}/", realm))?,
        })
    }
}


#[derive(Clone, Debug)]
pub struct KeycloakClient {
    config: KeycloakClientConfig,
    client: reqwest::Client,
    _user_cache: Arc<RwLock<HashMap<uuid::Uuid, (u64, User)>>>,
    _user_email_cache: Arc<RwLock<HashMap<String, (u64, uuid::Uuid)>>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "emailVerified", skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "firstName", skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName", skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "requiredActions", skip_serializing_if = "Option::is_none")]
    pub required_actions: Option<Vec<String>>,
    #[serde(rename = "realmRoles", skip_serializing_if = "Option::is_none")]
    pub realm_roles: Option<Vec<String>>,
    #[serde(rename = "clientRoles", skip_serializing_if = "Option::is_none")]
    pub client_roles: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, Vec<String>>>,
    #[serde(skip)]
    _client: Option<KeycloakClient>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Role {
    pub id: uuid::Uuid,
    pub name: String,
}

impl User {
    pub async fn update(&self, token: &str) -> Fallible<()> {
        let client = self._client.as_ref().unwrap();
        let u = client.config.base_url.join(&format!("users/{}", self.id.to_string()))?;

        crate::util::async_reqwest_to_error(
            client.client
                .put(u)
                .json(self)
                .bearer_auth(token)
        ).await?;
        Ok(())
    }

    pub async fn add_role(&mut self, new_roles: &[&str], token: &str) -> Fallible<()> {
        let client = self._client.as_ref().unwrap();

        let u = client.config.base_url.join(&format!("users/{}/role-mappings/realm/available", self.id.to_string()))?;

        let c = crate::util::async_reqwest_to_error(
            client.client
                .get(u)
                .bearer_auth(token)
        ).await?;
        let roles = c.json::<Vec<Role>>().await?;

        let roles_to_add = new_roles.into_iter().map(|r1| {
            match roles.iter().filter(|r2| {
                r2.name == r1.to_string()
            }).next() {
                Some(r) => Some(r.to_owned()),
                None => None
            }
        })
            .filter(|r| Option::is_some(r))
            .map(|r| r.unwrap())
            .collect::<Vec<Role>>();

        let r = client.config.base_url.join(&format!("users/{}/role-mappings/realm", self.id.to_string()))?;
        crate::util::async_reqwest_to_error(
            client.client.post(r)
                .json(&roles_to_add)
                .bearer_auth(token)
        ).await?;

        let realm_roles = match self.realm_roles.as_mut() {
            Some(m) => m,
            None => {
                let roles = vec![];
                self.realm_roles = Some(roles);
                self.realm_roles.as_mut().unwrap()
            }
        };
        realm_roles.append(&mut new_roles.into_iter().map(|s| s.to_string()).collect());
        Ok(())
    }

    pub async fn required_actions(&mut self, actions: &[&str], token: &str) -> Fallible<()> {
        let client = self._client.as_ref().unwrap();
        let mut actions: Vec<String> = actions.iter()
            .map(|a| a.to_string())
            .collect();

        let u = client.config.base_url.join(&format!("users/{}/execute-actions-email", self.id.to_string()))?;

        crate::util::async_reqwest_to_error(
            client.client
                .put(u)
                .json(&actions)
                .bearer_auth(token)
        ).await?;

        let required_actions = match self.required_actions.as_mut() {
            Some(m) => m,
            None => {
                let actions = vec![];
                self.required_actions = Some(actions);
                self.required_actions.as_mut().unwrap()
            }
        };
        required_actions.append(&mut actions);
        Ok(())
    }

    pub fn set_attribute(&mut self, attr: &str, value: &str) {
        let attributes = match self.attributes.as_mut() {
            Some(m) => m,
            None => {
                let map = HashMap::new();
                self.attributes = Some(map);
                self.attributes.as_mut().unwrap()
            }
        };
        attributes.insert(attr.to_owned(), vec![value.to_owned()]);
    }

    pub fn has_attribute(&self, attr: &str) -> bool {
        match &self.attributes {
            Some(a) => a.contains_key(attr),
            None => false
        }
    }

    pub fn get_attribute(&self, attr: &str) -> Option<String> {
        match &self.attributes {
            Some(a) => match a.get(attr) {
                Some(a) => match a.first() {
                    Some(s) => Some(s.to_owned()),
                    None => None
                },
                None => None
            },
            None => None
        }
    }
}

impl KeycloakClient {
    pub fn new(config: KeycloakClientConfig) -> Self {
        let mut d_headers = reqwest::header::HeaderMap::new();
        d_headers.insert(reqwest::header::CONTENT_TYPE, "application/json".parse().unwrap());

        Self {
            config,
            client: reqwest::Client::builder()
                .default_headers(d_headers)
                .build()
                .unwrap(),
            _user_cache: Arc::new(RwLock::new(HashMap::new())),
            _user_email_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_user(&self, user_id: uuid::Uuid, token: &str) -> actix_web::Result<User> {
        let since_the_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards").as_secs().to_owned();

        if let Some((insert_time, user)) = self._user_cache.read().unwrap().get(&user_id) {
            if insert_time.to_owned() > (since_the_epoch - 60) {
                return Ok(user.clone())
            }
        }

        let u = self.config.base_url.join(&format!("users/{}", user_id.to_string())).map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        let c = crate::util::async_reqwest_to_error(
            self.client
                .get(u)
                .bearer_auth(token)
        ).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        let mut u = c.json::<User>().await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        self._user_cache.write().unwrap().insert(user_id.clone(), (since_the_epoch, u.clone()));

        u._client = Some(self.clone());
        Ok(u)
    }

    pub async fn get_users(&self, token: &str) -> actix_web::Result<Vec<User>> {
        let u = self.config.base_url.join("users").map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        let c = crate::util::async_reqwest_to_error(
            self.client
                .get(u)
                .bearer_auth(token)
        ).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        let u = c.json::<Vec<User>>().await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?
            .into_iter()
            .map(|u| {
                let mut new_u = u.clone();
                new_u._client = Some(self.clone());
                u
            })
            .collect();
        Ok(u)
    }

    pub async fn get_users_expanded(&self, token: &str) -> actix_web::Result<Vec<User>> {
        let users = self.get_users(token).await?;
        let users: Vec<_> = users
            .into_iter()
            .map(|u| self.get_user(u.id, token))
            .collect();
        futures::future::try_join_all(users).await
    }

    pub async fn get_user_by_email(&self, check_email: &str, token: &str) -> actix_web::Result<Option<User>> {
        let since_the_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards").as_secs().to_owned();

        if let Some((insert_time, user_id)) = self._user_email_cache.read().unwrap().get(check_email) {
            if insert_time.to_owned() > (since_the_epoch - 60) {
                return Ok(Some(self.get_user(*user_id, token).await?))
            }
        }

        let users = self.get_users(token).await?;

        for user in users {
            if let Some(email) = &user.email {
                if email == check_email {
                    self._user_email_cache.write().unwrap().insert(check_email.to_string(), (since_the_epoch, user.id.clone()));

                    return Ok(Some(user));
                }
            }
        }

        Ok(None)
    }

    pub async fn create_user(&self, email: &str, token: &str) -> actix_web::Result<User> {
        let users = self.get_users(token).await?;

        fn username_exists(username: &str, users: &Vec<User>) -> bool {
            let mut users = users
                .iter()
                .filter(|u| {
                    if let Some(u) = &u.username {
                        u == username
                    } else {
                        false
                    }
                });

            match users.next() {
                Some(_) => true,
                None => false
            }
        }

        let mut preferred_username = email.to_string();
        while username_exists(&preferred_username, &users) {
            preferred_username = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();
        }

        let u = self.config.base_url.join("users").map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        let c = crate::util::async_reqwest_to_error(
            self.client
                .post(u)
                .json(&CreateUser {
                    username: preferred_username,
                    email: email.to_string(),
                    enabled: true,
                })
                .bearer_auth(token)
        ).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        let location_header = match c.headers().get(reqwest::header::LOCATION) {
            Some(l) => l,
            None => return Err(actix_web::error::ErrorInternalServerError("No location header"))
        };

        let location = location_header.to_str().map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        let location_url = reqwest::Url::parse(location).map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        let c = crate::util::async_reqwest_to_error(
            self.client
                .get(location_url)
                .bearer_auth(token)
        ).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        let mut r = c.json::<User>().await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
        r._client = Some(self.clone());
        Ok(r)
    }
}
