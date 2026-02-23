use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProfile {
    pub name: String,
    pub email: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl IdentityProfile {
    pub fn new(name: String, email: Option<String>) -> Self {
        Self {
            name,
            email,
            created_at: chrono::Utc::now(),
        }
    }
}
