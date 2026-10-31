//! Where secrets' values are kept (design §12, ADR 0022), behind one
//! interface. enclos's own records say which secrets a sandbox has; only the
//! store holds their values, and nothing writes a value anywhere else.

pub mod file;
pub mod keychain;
pub mod libsecret;
mod tool;

use std::cell::OnceCell;
use std::path::PathBuf;

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

/// The store of this host: on macOS the user's Keychain, or the keychain
/// file `ENCLOS_KEYCHAIN` names (for tests and CI), its items under
/// `service`, which names the enclos install; on Linux libsecret when a
/// Secret Service answers, else `file`.
pub fn host(service: String, file: PathBuf) -> Box<dyn SecretStore> {
    match cfg!(target_os = "macos") {
        true => Box::new(keychain::Keychain::from_env(service)),
        false => Box::new(Picked::new(
            Box::new(libsecret::Libsecret::from_env(service)),
            Box::new(file::FileStore::new(file)),
        )),
    }
}

/// A store that can say whether it can be reached at all.
pub trait Prober: SecretStore {
    fn answers(&self) -> bool;
}

/// The first store if it answers, else the second. It looks once, as a
/// secret is first needed: a command that needs none reaches no bus.
pub struct Picked {
    preferred: Box<dyn Prober>,
    otherwise: Box<dyn SecretStore>,
    answered: OnceCell<bool>,
}

impl Picked {
    pub fn new(preferred: Box<dyn Prober>, otherwise: Box<dyn SecretStore>) -> Picked {
        Picked {
            preferred,
            otherwise,
            answered: OnceCell::new(),
        }
    }

    fn store(&self) -> &dyn SecretStore {
        match self.answered.get_or_init(|| self.preferred.answers()) {
            true => &*self.preferred,
            false => &*self.otherwise,
        }
    }
}

impl SecretStore for Picked {
    fn set(&self, secret: &SecretRef, value: &SecretValue) -> Result<(), SecretError> {
        self.store().set(secret, value)
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<SecretValue>, SecretError> {
        self.store().get(secret)
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        self.store().remove(secret)
    }

    fn whereabouts(&self, secret: &SecretRef) -> String {
        self.store().whereabouts(secret)
    }

    fn env(&self) -> Vec<(String, String)> {
        self.store().env()
    }

    fn readable(&self) -> Result<(), SecretError> {
        self.store().readable()
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

/// The store in memory as a Secret Service that answers or does not,
/// counting the looks, in place of the real look at a session bus.
#[cfg(test)]
pub struct Stubbed {
    pub answers: bool,
    pub looks: std::rc::Rc<std::cell::Cell<usize>>,
    pub store: std::rc::Rc<InMemory>,
}

#[cfg(test)]
impl SecretStore for Stubbed {
    fn set(&self, secret: &SecretRef, value: &SecretValue) -> Result<(), SecretError> {
        self.store.set(secret, value)
    }

    fn get(&self, secret: &SecretRef) -> Result<Option<SecretValue>, SecretError> {
        self.store.get(secret)
    }

    fn remove(&self, secret: &SecretRef) -> Result<bool, SecretError> {
        self.store.remove(secret)
    }

    fn whereabouts(&self, secret: &SecretRef) -> String {
        self.store.whereabouts(secret)
    }
}

#[cfg(test)]
impl Prober for Stubbed {
    fn answers(&self) -> bool {
        self.looks.set(self.looks.get() + 1);
        self.answers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    fn secret() -> SecretRef {
        "home/telegram".parse().unwrap()
    }

    fn value() -> SecretValue {
        SecretValue::new("tok".to_owned()).unwrap()
    }

    struct Case {
        picked: Picked,
        service: Rc<InMemory>,
        file: Rc<InMemory>,
        looks: Rc<Cell<usize>>,
    }

    fn case(answers: bool) -> Case {
        let (service, file, looks) = (Rc::default(), Rc::default(), Rc::default());
        let picked = Picked::new(
            Box::new(Stubbed {
                answers,
                looks: Rc::clone(&looks),
                store: Rc::clone(&service),
            }),
            Box::new(Rc::clone(&file)),
        );
        Case {
            picked,
            service,
            file,
            looks,
        }
    }

    #[test]
    fn a_service_that_answers_is_picked() {
        let case = case(true);
        case.picked.set(&secret(), &value()).unwrap();
        assert!(case.service.0.borrow().contains_key(&secret()));
        assert!(case.file.0.borrow().is_empty());
    }

    #[test]
    fn no_service_answering_is_the_cue_to_use_the_file() {
        let case = case(false);
        case.picked.set(&secret(), &value()).unwrap();
        assert!(case.file.0.borrow().contains_key(&secret()));
        assert!(case.service.0.borrow().is_empty());
    }

    #[test]
    fn nothing_looks_until_a_secret_is_needed_and_then_once() {
        let case = case(true);
        assert_eq!(case.looks.get(), 0);
        case.picked.get(&secret()).unwrap();
        case.picked.remove(&secret()).unwrap();
        assert_eq!(case.looks.get(), 1);
    }
}
