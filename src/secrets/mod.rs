//! Where secrets' values are kept (design §12, ADR 0022), behind one
//! interface. enclos's own records say which secrets a sandbox has; only the
//! store holds their values, and nothing writes a value anywhere else.

pub mod keychain;

use crate::model::secret::{SecretRef, SecretValue};

/// Keeps secrets' values, outside every sandbox.
pub trait SecretStore {
    /// Stores `value` for `secret`, in place of any value it had.
    fn set(&self, secret: &SecretRef, value: &SecretValue) -> Result<(), SecretError>;
    /// The value of `secret`; `None` when the store has none.
    fn get(&self, secret: &SecretRef) -> Result<Option<SecretValue>, SecretError>;
    /// Removes `secret`'s value; false when the store had none.
    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError>;
    /// Where the store keeps `secret`, and how to remove it without enclos:
    /// for a secret enclos could not remove.
    fn whereabouts(&self, secret: &SecretRef) -> String;
    /// The variables with which another enclos process, such as a service,
    /// reaches this same store.
    fn env(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    /// Whether values can be read now without asking anyone: a locked
    /// keychain would ask to be unlocked, in a dialog nobody may see.
    fn readable(&self) -> Result<(), SecretError> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{what}")]
pub struct SecretError {
    pub what: String,
    /// The store refused before it changed anything: there is nothing to
    /// clean up after it.
    pub untouched: bool,
}

/// The store of this host: the user's Keychain on macOS, or the keychain
/// file `ENCLOS_KEYCHAIN` names (for tests and CI), its items under
/// `service`, which names the enclos install.
pub fn host(service: String) -> Box<dyn SecretStore> {
    match cfg!(target_os = "macos") {
        true => Box::new(keychain::Keychain::from_env(service)),
        false => Box::new(Unavailable {
            why: "secrets need the macOS Keychain on this build; libsecret and a 0600 file come with Linux (milestone 3)".to_owned(),
        }),
    }
}

/// No store: every call fails, saying why.
pub struct Unavailable {
    pub why: String,
}

impl SecretStore for Unavailable {
    fn set(&self, _: &SecretRef, _: &SecretValue) -> Result<(), SecretError> {
        Err(self.error())
    }

    fn get(&self, _: &SecretRef) -> Result<Option<SecretValue>, SecretError> {
        Err(self.error())
    }

    fn remove(&self, _: &SecretRef) -> Result<bool, SecretError> {
        Err(self.error())
    }

    fn whereabouts(&self, _: &SecretRef) -> String {
        format!("no secret store enclos can reach ({})", self.why)
    }
}

impl Unavailable {
    fn error(&self) -> SecretError {
        SecretError {
            what: self.why.clone(),
            untouched: true,
        }
    }
}

/// A copy of `value`, which is not `Clone`: a store in memory keeps its own.
#[cfg(test)]
fn copy(value: &SecretValue) -> SecretValue {
    SecretValue::new(value.expose().to_owned()).expect("a value already checked")
}

/// A store in memory, for tests of other components.
#[cfg(test)]
#[derive(Default)]
pub struct InMemory(
    pub std::cell::RefCell<std::collections::BTreeMap<SecretRef, SecretValue>>,
    /// Set, it answers as a locked keychain does: not readable.
    pub std::cell::Cell<bool>,
);

#[cfg(test)]
impl SecretStore for InMemory {
    fn set(&self, secret: &SecretRef, value: &SecretValue) -> Result<(), SecretError> {
        self.0.borrow_mut().insert(secret.clone(), copy(value));
        Ok(())
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<SecretValue>, SecretError> {
        Ok(self.0.borrow().get(secret).map(copy))
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        Ok(self.0.borrow_mut().remove(secret).is_some())
    }

    fn whereabouts(&self, secret: &SecretRef) -> String {
        format!("{secret} in memory")
    }

    fn readable(&self) -> Result<(), SecretError> {
        match self.1.get() {
            true => Err(SecretError {
                what: "the store in memory is locked".to_owned(),
                untouched: true,
            }),
            false => Ok(()),
        }
    }
}

#[cfg(test)]
impl<T: SecretStore> SecretStore for std::rc::Rc<T> {
    fn set(&self, secret: &SecretRef, value: &SecretValue) -> Result<(), SecretError> {
        (**self).set(secret, value)
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<SecretValue>, SecretError> {
        (**self).get(secret)
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        (**self).remove(secret)
    }

    fn whereabouts(&self, secret: &SecretRef) -> String {
        (**self).whereabouts(secret)
    }

    fn env(&self) -> Vec<(String, String)> {
        (**self).env()
    }

    fn readable(&self) -> Result<(), SecretError> {
        (**self).readable()
    }
}
