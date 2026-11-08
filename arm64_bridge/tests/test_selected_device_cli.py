"""Check the real harness refuses to choose a device by default."""
from pathlib import Path
import subprocess
import sys


if __name__ == '__main__':
    script = Path(__file__).resolve().parents[1] / 'test_bridge.py'
    result = subprocess.run([sys.executable, '-B', str(script), 'probe'],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2, result.stdout + result.stderr
    assert '--serial' in result.stderr, result.stderr
    assert 'get_state:' not in result.stdout, result.stdout
    print('PASS: no device is selected without an explicit serial')
