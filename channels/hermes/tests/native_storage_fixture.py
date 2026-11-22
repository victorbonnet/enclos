"""Test-owned storage binding for current and legacy public ingress contracts."""
from dataclasses import asdict
from pathlib import Path
import importlib.util

CURRENT = importlib.util.find_spec('persistence_assembly') is not None
if CURRENT:
    from persistence_assembly import open_persistence, profile_scope
    from persistence.core.errors import AuthorityRefusal as RuntimeStoreError
    from persistence.conversation.sessions import NewSession
    def SessionDB(path):
        return open_persistence(profile_scope(home=Path(path).parent))
    def create_session(db, session_id):
        db.sessions.create(NewSession(session_id=session_id, source='test'))
    def begin_runtime_epoch(db, **kwargs):
        return db.runtime.begin_epoch(**kwargs)
    def get_session_admission(db, **kwargs):
        record = db.admissions.get(**kwargs)
        return asdict(record) if record else None
    def admit_session_input(db, **kwargs):
        record, _ = db.admissions.admit(**kwargs)
        return asdict(record)
    def cancel_session_input(db, **kwargs):
        return db.admissions.cancel(**kwargs)
else:
    from hermes_state import SessionDB
    from hermes_state_runtime import (RuntimeStoreError, begin_runtime_epoch,
        get_session_admission, admit_session_input, cancel_session_input)
    def create_session(db, session_id):
        db.create_session(session_id, source='test')
