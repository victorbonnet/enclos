//! Where secrets' values are kept (design §12, ADR 0022), behind one
//! interface. enclos's own records say which secrets a sandbox has; only the
//! store holds their values, and nothing writes a value anywhere else.

pub mod keychain;

use crate::model::secret::SecretRef;

/// Keeps secrets' values, outside every sandbox.
pub trait SecretStore {
    /// Stores `value` for `secret`, in place of any value it had.
    fn set(&self, secret: &SecretRef, value: &str) -> Result<(), SecretError>;
    /// The value of `secret`; `None` when the store has none.
    fn get(&self, secret: &SecretRef) -> Result<Option<String>, SecretError>;
    /// Removes `secret`'s value; false when the store had none.
    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{what}")]
pub struct SecretError {
    pub what: String,
}

/// The store of this host: the user's Keychain on macOS, or the keychain
/// file `ENCLOS_KEYCHAIN` names (for tests and CI), its items under
/// `service`, which names the enclos install.
pub fn host(service: String) -> Box<dyn SecretStore> {
    match cfg!(target_os = "macos") {
        true => Box::new(keychain::Keychain::from_env(service)),
        false => Box::new(Unavailable {
            why: "secrets need the macOS Keychain on this build; libsecret and a 0600 file come with Linux (milestone 3)",
        }),
    }
}

/// No store: every call fails, saying why.
pub struct Unavailable {
    pub why: &'static str,
}

impl SecretStore for Unavailable {
    fn set(&self, _: &SecretRef, _: &str) -> Result<(), SecretError> {
        Err(self.error())
    }

    fn get(&self, _: &SecretRef) -> Result<Option<String>, SecretError> {
        Err(self.error())
    }

    fn remove(&self, _: &SecretRef) -> Result<bool, SecretError> {
        Err(self.error())
    }
}

impl Unavailable {
    fn error(&self) -> SecretError {
        SecretError {
            what: self.why.to_owned(),
        }
    }
}

/// A store in memory, for tests of other components.
#[cfg(test)]
#[derive(Default)]
pub struct InMemory(pub std::cell::RefCell<std::collections::BTreeMap<SecretRef, String>>);

#[cfg(test)]
impl SecretStore for InMemory {
    fn set(&self, secret: &SecretRef, value: &str) -> Result<(), SecretError> {
        self.0.borrow_mut().insert(secret.clone(), value.to_owned());
        Ok(())
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<String>, SecretError> {
        Ok(self.0.borrow().get(secret).cloned())
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        Ok(self.0.borrow_mut().remove(secret).is_some())
    }
}

#[cfg(test)]
impl SecretStore for std::rc::Rc<InMemory> {
    fn set(&self, secret: &SecretRef, value: &str) -> Result<(), SecretError> {
        (**self).set(secret, value)
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<String>, SecretError> {
        (**self).get(secret)
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        (**self).remove(secret)
    }
}
