from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path


class BrokerSmokeIntegrationTests(unittest.TestCase):
    def test_broker_examples(self) -> None:
        if os.getenv('AEGIS_RUN_BROKER_SMOKE') != '1':
            self.skipTest('set AEGIS_RUN_BROKER_SMOKE=1 to run live broker smoke examples')
        if not os.getenv('AEGIS_CRED_GITHUB_TOKEN'):
            self.skipTest('AEGIS_CRED_GITHUB_TOKEN is required for live broker smoke examples')

        repo_root = Path(__file__).resolve().parents[3]
        examples_dir = repo_root / 'sdk/python/examples'
        for script_name in ('broker_allowed.py', 'broker_denied.py'):
            completed = subprocess.run(
                [sys.executable, str(examples_dir / script_name)],
                cwd=repo_root,
                check=False,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=f'{script_name} failed\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}',
            )
