//! A service manager for tests: it records what it was asked and runs
//! nothing.

use std::cell::RefCell;

use super::{ServiceError, ServiceManager, ServiceStatus, ServiceUnit};

#[derive(Default)]
pub struct FakeServices {
    pub started: RefCell<Vec<ServiceUnit>>,
    pub stopped: RefCell<Vec<String>>,
}

impl ServiceManager for FakeServices {
    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        self.started.borrow_mut().push(unit.clone());
        Ok(())
    }

    fn stop(&self, label: &str) -> Result<(), ServiceError> {
        self.started.borrow_mut().retain(|u| u.label != label);
        self.stopped.borrow_mut().push(label.to_owned());
        Ok(())
    }

    fn status(&self, label: &str) -> ServiceStatus {
        if self.started.borrow().iter().any(|u| u.label == label) {
            ServiceStatus::Loaded
        } else {
            ServiceStatus::NotLoaded
        }
    }
}

/// Shared, so a test keeps a handle on what the engine asked.
impl ServiceManager for std::rc::Rc<FakeServices> {
    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        self.as_ref().start(unit)
    }

    fn stop(&self, label: &str) -> Result<(), ServiceError> {
        self.as_ref().stop(label)
    }

    fn status(&self, label: &str) -> ServiceStatus {
        self.as_ref().status(label)
    }
}
