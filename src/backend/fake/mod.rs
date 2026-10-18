//! A backend for tests: it reports whatever kind and probe it is given and
//! touches nothing on the host.

use super::{Backend, Probe};
use crate::model::sandbox::BackendKind;

pub struct FakeBackend {
    kind: BackendKind,
    probe: Probe,
}

impl FakeBackend {
    /// A fake that stands in for `kind` and is available.
    pub fn available(kind: BackendKind) -> Self {
        FakeBackend {
            kind,
            probe: Probe::Available,
        }
    }

    /// A fake that stands in for `kind` and is unavailable for `reason`.
    pub fn unavailable(kind: BackendKind, reason: &str) -> Self {
        FakeBackend {
            kind,
            probe: Probe::Unavailable {
                reason: reason.to_owned(),
            },
        }
    }
}

impl Backend for FakeBackend {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn probe(&self) -> Probe {
        self.probe.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_what_it_was_given() {
        let fake = FakeBackend::unavailable(BackendKind::Bubblewrap, "not Linux");
        assert_eq!(fake.kind(), BackendKind::Bubblewrap);
        assert_eq!(
            fake.probe(),
            Probe::Unavailable {
                reason: "not Linux".into()
            }
        );
        assert_eq!(
            FakeBackend::available(BackendKind::Seatbelt).probe(),
            Probe::Available
        );
    }
}
