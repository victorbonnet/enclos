//! A service manager for tests: it records what it was asked and runs
//! nothing.

use std::cell::RefCell;

use super::{ServiceError, ServiceLabel, ServiceManager, ServiceStatus, ServiceUnit};

#[derive(Default)]
pub struct FakeServices {
    pub started: RefCell<Vec<ServiceUnit>>,
    pub stopped: RefCell<Vec<ServiceLabel>>,
    /// Starts of labels ending with this fail.
    pub refuse: RefCell<Option<String>>,
    /// Stops of labels ending with this fail.
    pub refuse_stop: RefCell<Option<String>>,
    /// Runs after each stop that worked, given its label, for a test to act
    /// in between.
    pub on_stop: RefCell<Option<Meanwhile>>,
    /// Processes a test started to stand in for a unit's job: stopping the
    /// unit ends and reaps them, as launchd's `bootout` waits for the job
    /// to exit.
    pub jobs: RefCell<Vec<(ServiceLabel, std::process::Child)>>,
    /// Listing the installed units fails, as when launchd does not answer.
    pub refuse_installed: RefCell<bool>,
}

pub type Meanwhile = Box<dyn Fn(&ServiceLabel)>;

impl FakeServices {
    /// As if a unit were installed, by an earlier enclos or by hand.
    pub fn seed(&self, label: &str) {
        self.started.borrow_mut().push(ServiceUnit {
            label: ServiceLabel::parse(label).unwrap(),
            program: "/usr/local/bin/enclos".into(),
            args: Vec::new(),
            log: "/dev/null".into(),
            env: Vec::new(),
            stop_timeout: std::time::Duration::ZERO,
        });
    }
}

impl ServiceManager for FakeServices {
    fn available(&self) -> Result<(), ServiceError> {
        Ok(())
    }

    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        if let Some(end) = self.refuse.borrow().as_deref()
            && unit.label.as_str().ends_with(end)
        {
            return Err(ServiceError {
                what: format!("refused {}", unit.label),
            });
        }
        // As launchd's `start`, a unit already there is replaced.
        self.started.borrow_mut().retain(|u| u.label != unit.label);
        self.started.borrow_mut().push(unit.clone());
        Ok(())
    }

    fn stop(&self, label: &ServiceLabel) -> Result<(), ServiceError> {
        if let Some(end) = self.refuse_stop.borrow().as_deref()
            && label.as_str().ends_with(end)
        {
            return Err(ServiceError {
                what: format!("would not stop {label}"),
            });
        }
        self.started.borrow_mut().retain(|u| u.label != *label);
        self.stopped.borrow_mut().push(label.clone());
        for (_, mut job) in self.jobs.borrow_mut().extract_if(.., |(l, _)| l == label) {
            let _ = job.kill();
            let _ = job.wait();
        }
        if let Some(meanwhile) = self.on_stop.borrow().as_ref() {
            meanwhile(label);
        }
        Ok(())
    }

    fn status(&self, label: &ServiceLabel) -> Result<ServiceStatus, ServiceError> {
        Ok(if self.started.borrow().iter().any(|u| u.label == *label) {
            ServiceStatus::Loaded
        } else {
            ServiceStatus::NotLoaded
        })
    }

    fn installed(&self, prefix: &str) -> Result<Vec<ServiceLabel>, ServiceError> {
        if *self.refuse_installed.borrow() {
            return Err(ServiceError {
                what: "the service manager did not answer".into(),
            });
        }
        Ok(self
            .started
            .borrow()
            .iter()
            .map(|u| u.label.clone())
            .filter(|l| l.as_str().starts_with(prefix))
            .collect())
    }
}

/// Shared, so a test keeps a handle on what the engine asked.
impl ServiceManager for std::rc::Rc<FakeServices> {
    fn available(&self) -> Result<(), ServiceError> {
        self.as_ref().available()
    }

    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        self.as_ref().start(unit)
    }

    fn stop(&self, label: &ServiceLabel) -> Result<(), ServiceError> {
        self.as_ref().stop(label)
    }

    fn status(&self, label: &ServiceLabel) -> Result<ServiceStatus, ServiceError> {
        self.as_ref().status(label)
    }

    fn installed(&self, prefix: &str) -> Result<Vec<ServiceLabel>, ServiceError> {
        self.as_ref().installed(prefix)
    }
}
