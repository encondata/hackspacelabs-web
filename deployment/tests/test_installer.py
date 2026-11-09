"""Installer orchestration tests; Docker/Git network operations are stubbed."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.destination = self.base / 'install with spaces'
        self.log = self.base / 'calls'
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        TEST_LOG=str(self.log), TEST_SOURCE=str(ROOT))
        self.stub('docker', '''printf 'docker %s\\n' "$*" >> "$TEST_LOG"
if [[ "${TEST_FAIL:-}" == 1 && "$*" == *'up -d'* ]]; then exit 1; fi
''')
        self.stub('git', '''printf 'git %s\\n' "$*" >> "$TEST_LOG"
if [[ "$1" == clone ]]; then
  target="${@: -1}"
  mkdir -p "$target/.git" "$target/deployment/scripts"
  cp "$TEST_SOURCE/deployment/scripts/setup.sh" "$target/deployment/scripts/"
elif [[ "$*" == *'rev-parse --show-toplevel'* ]]; then printf '%s\\n' "$2"
elif [[ "$*" == *'remote get-url origin'* ]]; then printf '%s\\n' "${TEST_ORIGIN:-https://github.com/encondata/hackspacelabs-web.git}"
elif [[ "$*" == *'status --porcelain'* ]]; then printf '%s' "${TEST_DIRTY:-}"
elif [[ "$*" == *'branch --show-current'* ]]; then echo main
fi
''')

    def stub(self, name, body):
        p = self.bin / name
        p.write_text('#!/usr/bin/env bash\nset -eu\n'+body)
        p.chmod(0o755)

    def run_install(self, options='\n\n\n\n'):
        return subprocess.run(['bash',str(ROOT/'install.sh')],
            input=str(self.destination)+'\n'+options, text=True, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_first_install_then_update_preserves_secrets(self):
        first=self.run_install()
        self.assertEqual(first.returncode,0,first.stderr)
        envfile=self.destination/'deployment/.env'
        contents=envfile.read_text()
        self.assertIn('BIND_ADDRESS=0.0.0.0',contents)
        self.assertIn('WEB_PORT=8088',contents)
        self.assertEqual(envfile.stat().st_mode & 0o777,0o600)
        for line in contents.splitlines():
            if line.startswith('SESSION_SECRET='):
                secret=line.split('=',1)[1]
                self.assertEqual(len(secret),96)
                self.assertNotIn(secret,first.stdout+first.stderr)
        second=self.run_install('')
        self.assertEqual(second.returncode,0,second.stderr)
        self.assertEqual(envfile.read_text(),contents)
        self.assertIn('pull --ff-only origin main',self.log.read_text())
        self.assertFalse(Path(str(self.destination)+'.install-lock').exists())

    def test_refuses_nonempty_directory(self):
        self.destination.mkdir()
        (self.destination/'keep.txt').write_text('keep')
        result=self.run_install()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((self.destination/'keep.txt').read_text(),'keep')
        self.assertNotIn('git clone',self.log.read_text())

    def test_dirty_checkout_is_not_pulled(self):
        self.assertEqual(self.run_install().returncode,0)
        self.log.write_text('')
        self.env['TEST_DIRTY']=' M README.md'
        self.assertNotEqual(self.run_install('').returncode,0)
        self.assertNotIn('pull',self.log.read_text())

    def test_wrong_origin_is_not_pulled(self):
        self.assertEqual(self.run_install().returncode,0)
        self.log.write_text('')
        self.env['TEST_ORIGIN']='https://github.com/example/other.git'
        self.assertNotEqual(self.run_install('').returncode,0)
        self.assertNotIn('pull',self.log.read_text())

    def test_unhealthy_start_is_failure_and_preserves_env(self):
        self.env['TEST_FAIL']='1'
        result=self.run_install()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('not a successful installation',result.stderr)
        self.assertTrue((self.destination/'deployment/.env').exists())
        self.assertFalse(Path(str(self.destination)+'.install-lock').exists())

    def test_rejects_duplicate_ports(self):
        result=self.run_install('\n\n8088\n8088\n')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.destination/'deployment/.env').exists())

    def test_rejects_url_instead_of_hostname(self):
        self.assertNotEqual(self.run_install('https://example.com\n').returncode,0)
        self.assertFalse((self.destination/'deployment/.env').exists())

    def test_config_is_not_executed_as_shell(self):
        self.assertEqual(self.run_install().returncode,0)
        marker=self.base/'bad'
        with (self.destination/'deployment/.env').open('a') as f:
            f.write('\nUNTRUSTED=$(touch '+str(marker)+')\n')
        self.assertEqual(self.run_install('').returncode,0)
        self.assertFalse(marker.exists())

if __name__ == '__main__':
    unittest.main(verbosity=2)
