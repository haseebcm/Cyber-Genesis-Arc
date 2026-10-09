"""Demonstrate real OS enforcement against a disposable heartbeat child."""
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from h11_cga.response import ProcessResponseController


def main():
    with tempfile.TemporaryDirectory(prefix='h11-live-proof-') as directory:
        heartbeat = Path(directory)/'heartbeat.txt'
        script = "import sys,time; from pathlib import Path\np=Path(sys.argv[1])\nwhile True:\n p.write_text(str(time.time()))\n time.sleep(.05)\n"
        child = subprocess.Popen([sys.executable, '-c', script, str(heartbeat)])
        controller = None
        try:
            timeout = time.monotonic() + 5
            while not heartbeat.exists():
                if time.monotonic() >= timeout:
                    raise RuntimeError('Child failed to start')
                time.sleep(.05)
            controller = ProcessResponseController([child.pid], Path(directory)/'audit.sqlite3', 3)
            print('Real disposable process PID:', child.pid)
            response = controller.quarantine(child.pid, 'Live presentation proof', 2)
            time.sleep(.1)
            frozen = heartbeat.stat().st_mtime_ns
            time.sleep(.4)
            assert heartbeat.stat().st_mtime_ns == frozen, 'Heartbeat did not stop'
            print('OS suspension verified: real heartbeat stopped')
            timeout = time.monotonic()+8
            while controller.audit.get(response['id'])['state'] != 'RESUMED':
                if time.monotonic() >= timeout:
                    raise RuntimeError('Automatic rollback failed')
                time.sleep(.1)
            timeout = time.monotonic()+3
            while heartbeat.stat().st_mtime_ns == frozen:
                if time.monotonic() >= timeout:
                    raise RuntimeError('Heartbeat did not resume')
                time.sleep(.05)
            print('Automatic rollback verified: real heartbeat resumed')
            print('Durable audit transitions:', [r['kind'] for r in reversed(controller.audit.recent())])
        finally:
            if controller:
                controller.close()
            child.terminate()
            child.wait(timeout=10)


if __name__ == '__main__':
    main()
