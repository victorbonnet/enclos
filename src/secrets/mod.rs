//! Where secrets' values are kept (design §12, ADR 0022), behind one
//! interface. enclos's own records say which secrets a sandbox has; only the
//! store holds their values, and nothing writes a value anywhere else.

pub mod file;
pub mod keychain;
pub mod libsecret;
mod tool;

use std::cell::OnceCell;
use std::path::PathBuf;

use crate::model::secret::{SecretRef, SecretValue, StoreName};

/// Keeps secrets' values, outside every sandbox.
pub trait SecretStore {
    /// Which store this is, as a secret's record names it.
    fn name(&self) -> StoreName;
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
pub fn host(service: String, file: PathBuf) -> Box<dyn Stores> {
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

/// The stores of a host, each secret in the one its record names: a value is
/// only ever looked for there, never in another store.
pub trait Stores {
    /// The store a new secret goes to.
    fn for_new(&self) -> Result<&dyn SecretStore, SecretError>;
    /// The store `name`, the one a secret's record names, if it answers.
    fn recorded(&self, name: StoreName) -> Result<&dyn SecretStore, SecretError>;
    /// The variables with which a service reaches these stores.
    fn service_env(&self) -> Vec<(String, String)>;
}

/// A store alone is a host's only one.
impl<T: SecretStore> Stores for T {
    fn for_new(&self) -> Result<&dyn SecretStore, SecretError> {
        Ok(self)
    }

    fn recorded(&self, name: StoreName) -> Result<&dyn SecretStore, SecretError> {
        match name == self.name() {
            true => Ok(self),
            false => Err(not_on_this_host(name)),
        }
    }

    fn service_env(&self) -> Vec<(String, String)> {
        self.env()
    }
}

fn not_on_this_host(name: StoreName) -> SecretError {
    SecretError {
        what: format!(
            "it is in {}, which this host does not have, and enclos never looks for it in another store",
            name.shown()
        ),
        untouched: true,
    }
}

/// The first store if it answers, else the second, for a new secret; a
/// recorded one stays in its store, which is refused when it does not answer.
/// It looks once, and only for what needs the first store.
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

    fn answers(&self) -> bool {
        *self.answered.get_or_init(|| self.preferred.answers())
    }
}

impl Stores for Picked {
    fn for_new(&self) -> Result<&dyn SecretStore, SecretError> {
        Ok(match self.answers() {
            true => &*self.preferred,
            false => &*self.otherwise,
        })
    }

    fn recorded(&self, name: StoreName) -> Result<&dyn SecretStore, SecretError> {
        if name == self.otherwise.name() {
            return Ok(&*self.otherwise);
        }
        if name != self.preferred.name() {
            return Err(not_on_this_host(name));
        }
        match self.answers() {
            true => Ok(&*self.preferred),
            false => Err(SecretError {
                what: format!(
                    "it is in {}, which does not answer here, and enclos never looks for it in another store; run this where it answers",
                    name.shown()
                ),
                untouched: true,
            }),
        }
    }

    fn service_env(&self) -> Vec<(String, String)> {
        let mut env = self.preferred.env();
        env.extend(self.otherwise.env());
        env
    }
}

/// No store: every call fails, saying why.
pub struct Unavailable {
    pub why: String,
}

impl Stores for Unavailable {
    fn for_new(&self) -> Result<&dyn SecretStore, SecretError> {
        Err(self.error())
    }

    fn recorded(&self, _: StoreName) -> Result<&dyn SecretStore, SecretError> {
        Err(self.error())
    }

    fn service_env(&self) -> Vec<(String, String)> {
        Vec::new()
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
    /// The store it stands for; none, the Keychain.
    pub std::cell::Cell<Option<StoreName>>,
);

#[cfg(test)]
impl InMemory {
    /// Standing for the store `name`.
    pub fn named(name: StoreName) -> InMemory {
        let store = InMemory::default();
        store.2.set(Some(name));
        store
    }
}

#[cfg(test)]
impl SecretStore for InMemory {
    fn name(&self) -> StoreName {
        self.2.get().unwrap_or(StoreName::Keychain)
    }

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
    fn name(&self) -> StoreName {
        (**self).name()
    }

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
    fn name(&self) -> StoreName {
        self.store.name()
    }

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
        let service = Rc::new(InMemory::named(StoreName::Libsecret));
        let file = Rc::new(InMemory::named(StoreName::File));
        let looks = Rc::default();
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
        let store = case.picked.for_new().unwrap();
        assert_eq!(store.name(), StoreName::Libsecret);
        store.set(&secret(), &value()).unwrap();
        assert!(case.service.0.borrow().contains_key(&secret()));
        assert!(case.file.0.borrow().is_empty());
    }

    #[test]
    fn no_service_answering_is_the_cue_to_use_the_file() {
        let case = case(false);
        let store = case.picked.for_new().unwrap();
        assert_eq!(store.name(), StoreName::File);
        store.set(&secret(), &value()).unwrap();
        assert!(case.file.0.borrow().contains_key(&secret()));
        assert!(case.service.0.borrow().is_empty());
    }

    #[test]
    fn nothing_looks_until_a_secret_is_needed_and_then_once() {
        let case = case(true);
        assert_eq!(case.looks.get(), 0);
        case.picked.for_new().unwrap().get(&secret()).unwrap();
        case.picked.recorded(StoreName::Libsecret).unwrap();
        assert_eq!(case.looks.get(), 1);
    }

    /// A recorded secret stays where it is, and the file needs no bus.
    #[test]
    fn a_secret_in_the_file_is_reached_with_no_look_at_the_bus() {
        let case = case(true);
        let store = case.picked.recorded(StoreName::File).unwrap();
        assert_eq!(store.name(), StoreName::File);
        assert_eq!(case.looks.get(), 0);
    }

    /// Never the file instead, for a value that is elsewhere.
    #[test]
    fn a_recorded_store_that_does_not_answer_is_refused() {
        let case = case(false);
        let err = case
            .picked
            .recorded(StoreName::Libsecret)
            .err()
            .expect("refused");
        assert!(err.untouched, "{err}");
        assert!(err.what.contains("the Secret Service"), "{err}");
        assert!(err.what.contains("does not answer"), "{err}");
    }

    #[test]
    fn a_store_this_host_does_not_have_is_refused() {
        for answers in [true, false] {
            let err = case(answers)
                .picked
                .recorded(StoreName::Keychain)
                .err()
                .expect("refused");
            assert!(err.what.contains("the Keychain"), "{err}");
        }
        let alone = InMemory::named(StoreName::File);
        assert!(alone.recorded(StoreName::File).is_ok());
        assert!(alone.recorded(StoreName::Keychain).is_err());
    }
}
