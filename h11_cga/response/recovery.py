"""Detached deadline watchdog for one durably recorded response."""
import sys
import time
from .audit import AuditStore
from .process import ProcessResponseController


def main():
    journal = AuditStore(sys.argv[1])
    try:
        row = journal.get(sys.argv[2])
        if not row:
            return
        journal.watchdog_ready(row['id'])
        pending_deadline = time.monotonic() + 10
        deadline = None
        while True:
            row = journal.get(sys.argv[2])
            if not row or row['state'] not in {'PENDING', 'SUSPENDED', 'RECOVERY_FAILED'}:
                return
            if row['state'] == 'PENDING':
                expired = time.monotonic() >= pending_deadline
            else:
                if deadline is None:
                    deadline = time.monotonic() + max(0, min(300, row['deadline'] - time.time()))
                expired = time.monotonic() >= deadline
            if expired:
                controller = object.__new__(ProcessResponseController)
                controller.audit = journal
                controller._resume_row(row, recovery=True)
            time.sleep(.2)
    finally:
        journal.close()


if __name__ == '__main__':
    main()
