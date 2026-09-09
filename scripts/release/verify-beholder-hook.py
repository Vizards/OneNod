"""Exercise the actual packaged executables with the managed command and dummy events."""
import argparse
import base64
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest

MANAGED_GUARD = '/Library/Application Support/Beholder/codex-hooks/beholder-e1-context'
MANAGED_SOCKET = '/Library/Application Support/Beholder/run/core.sock'
WORKER_NAME = 'beholder-e1-pretool-hook'
WORKER_IDENTITY = {'component': 'beholder-context-worker', 'schema_version': 1, 'relay_schema_version': 1}
GUARD_IDENTITY = {'component': 'beholder-context-guard', 'schema_version': 1,
                  'worker': WORKER_NAME, 'deadline_ms': 3000}


def managed_command(guard=MANAGED_GUARD, core_socket=MANAGED_SOCKET):
    # Codex reserves status 2 for a policy block. Normalize the outer command too,
    # including a missing/corrupt guard; never parse component output as policy.
    return (shlex.quote(str(guard)) + ' --core-socket ' + shlex.quote(str(core_socket)) +
            " >/dev/null 2>&1 || :; printf '{}\\n'; exit 0")


def commands_from_config(data):
    commands = [json.loads(line.split('=', 1)[1].strip())
                for line in data.decode().splitlines() if line.startswith('command = ')]
    if len(commands) not in (2, 6) or any(command != managed_command() for command in commands):
        raise RuntimeError('Managed Hook command differs from the reviewed availability contract')
    timeouts = [json.loads(line.split('=', 1)[1].strip())
                for line in data.decode().splitlines() if line.startswith('timeout = ')]
    if len(timeouts) != len(commands) or any(type(value) is not int or value < 5 for value in timeouts):
        raise RuntimeError('Managed Hook timeout must leave shutdown margin after the three-second watchdog')
    return commands


def hook_run_options(run_as_user=None):
    options = {'env': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': os.path.expanduser('~')}}
    if run_as_user is not None:
        options.update(user=run_as_user, group=20, extra_groups=[])
    return options


def verify_hook_contract(guard, config=None, run_as_user=None):
    guard = Path(guard)
    worker = guard.with_name(WORKER_NAME)
    options = hook_run_options(run_as_user)
    for path, identity in [(guard, GUARD_IDENTITY), (worker, WORKER_IDENTITY)]:
        result = subprocess.run([str(path), '--identity'], capture_output=True, timeout=4, **options)
        if result.returncode != 0 or result.stderr or json.loads(result.stdout) != identity:
            raise RuntimeError('Packaged Hook component identity mismatch: ' + path.name)
    commands = commands_from_config(config) if config is not None else [managed_command()] * 2
    report = []
    # Keep the Unix address short; all content here is disposable dummy data.
    with tempfile.TemporaryDirectory(prefix='beholder-contract-', dir='/private/tmp') as temporary:
        root = Path(temporary)
        transcript = root / 'session.jsonl'
        transcript.write_text(json.dumps({'type': 'session_meta',
            'payload': {'id': 'hook-contract-session', 'cwd': str(root)}}) + '\n')
        transcript.chmod(0o600)
        if run_as_user is not None:
            os.chown(root, run_as_user, 20)
            os.chown(transcript, run_as_user, 20)
        events = ['UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop', 'Interrupt', 'SessionEnd'][:len(commands)]
        for index, event_name in enumerate(events):
            address = root / 'core.sock'
            event = {'session_id': 'hook-contract-session', 'turn_id': 'hook-contract-turn',
                'transcript_path': str(transcript), 'cwd': str(root / 'sibling-project'), 'model': 'gpt-5.6-luna',
                'permission_mode': 'dontAsk', 'hook_event_name': event_name}
            if event_name == 'UserPromptSubmit':
                event['prompt'] = 'Beholder packaging acceptance dummy prompt'
            elif event_name == 'PreToolUse':
                event.update(tool_name='functions.exec', tool_use_id='hook-contract-tool',
                             tool_input='await tools.exec_command({cmd: "true"});')
            elif event_name == 'PostToolUse':
                event.update(tool_name='Bash', tool_use_id='hook-contract-tool', tool_response={'exit_code': 0})
            elif event_name == 'SessionEnd':
                event.pop('turn_id')
            received, errors = [], []
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(address))
                address.chmod(0o600)
                if run_as_user is not None:
                    os.chown(address, run_as_user, 20)
                listener.listen(1)
                listener.settimeout(4)

                def serve():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(2)
                            data = b''
                            while b'\n' not in data and len(data) < 4 * 1024 * 1024:
                                chunk = connection.recv(65536)
                                if not chunk:
                                    break
                                data += chunk
                            received.append(json.loads(data))
                            response = {'schema_version': 1, 'accepted': True}
                            if event_name == 'PreToolUse':
                                response['tool_ref'] = 'tool-selector-' + '0' * 64
                            connection.sendall(json.dumps(response).encode() + b'\n')
                    except BaseException as error:
                        errors.append(type(error).__name__)

                server = threading.Thread(target=serve)
                server.start()
                command = commands[index].replace(shlex.quote(MANAGED_GUARD), shlex.quote(str(guard)))
                command = command.replace(shlex.quote(MANAGED_SOCKET), shlex.quote(str(address)))
                start = time.monotonic()
                try:
                    result = subprocess.run(['/bin/sh', '-c', command], input=json.dumps(event).encode(),
                                            capture_output=True, timeout=4.5, **options)
                finally:
                    server.join(timeout=4.5)
                elapsed = time.monotonic() - start
            address.unlink()
            if server.is_alive() or errors or len(received) != 1:
                raise RuntimeError('Packaged Hook did not relay the ' + event_name + ' event')
            if result.returncode != 0 or result.stdout != b'{}\n' or result.stderr:
                raise RuntimeError('Packaged Hook changed the Codex continuation response')
            request = received[0]
            lifecycle = event_name in ('PostToolUse', 'Stop', 'Interrupt', 'SessionEnd')
            kind = 'execution-lifecycle' if lifecycle else ('prompt-observation' if event_name == 'UserPromptSubmit' else 'host-observation')
            if request.get('kind') != kind or request.get('schema_version') != 1:
                raise RuntimeError('Wrong Hook relay component or schema')
            field = 'lifecycle' if lifecycle else ('prompt' if event_name == 'UserPromptSubmit' else 'host')
            observation = request[field]
            keys = ['session_id', 'transcript_path'] if lifecycle else ['session_id', 'turn_id', 'transcript_path', 'cwd', 'hook_event_name']
            for key in keys:
                if observation.get(key) != event[key]:
                    raise RuntimeError('Hook relay changed event binding: ' + key)
            if lifecycle:
                if observation.get('event') != event_name or observation.get('turn_id', '') != event.get('turn_id', ''):
                    raise RuntimeError('Hook relay changed lifecycle binding')
                if event_name == 'PostToolUse' and not observation.get('terminal'):
                    raise RuntimeError('Hook relay lost structured terminal exit')
            elif event_name == 'UserPromptSubmit':
                if base64.b64decode(observation['prompt']).decode() != event['prompt']:
                    raise RuntimeError('Hook relay changed the prompt')
            elif observation.get('tool_input') != event['tool_input']:
                raise RuntimeError('Hook relay changed the tool input')
            report.append({'event': event_name, 'relayed': True, 'exit_code': 0,
                           'elapsed_ms': round(elapsed * 1000)})
    return report


MAY_BINARY = None


class GuardTests(unittest.TestCase):
    def test_host_timeout_retains_watchdog_shutdown_margin(self):
        config = Path(__file__).resolve().parents[2] / 'cmd/may/internal/beholdercontext/managed.example.toml'
        data = config.read_bytes()
        commands_from_config(data)
        with self.assertRaisesRegex(RuntimeError, 'shutdown margin'):
            commands_from_config(data.replace(b'timeout = 5', b'timeout = 3', 1))

    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='beholder-release-', dir='/private/tmp')
        cls.binary = Path(cls.build.name) / 'beholder-e1-context'
        cls.worker = Path(cls.build.name) / WORKER_NAME
        shutil.copy2(MAY_BINARY, cls.binary)
        shutil.copy2(MAY_BINARY, cls.worker)
        cls.binary.chmod(0o700)
        cls.worker.chmod(0o700)

    @classmethod
    def tearDownClass(cls):
        if cls.build is not None:
            cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='beholder-case-', dir='/private/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.guard = self.root / self.binary.name
        self.worker_path = self.root / WORKER_NAME
        shutil.copy2(self.binary, self.guard)

    def worker_script(self, code):
        self.worker_path.write_text('#!/bin/sh\n' + code + '\n')
        self.worker_path.chmod(0o700)

    def assert_continues(self, args=(), input=b'{}', command=False):
        argv = ['/bin/sh', '-c', managed_command(self.guard, '/private/tmp/missing-core.sock')] if command else [str(self.guard), *args]
        start = time.monotonic()
        result = subprocess.run(argv, input=input, capture_output=True, timeout=4.5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'{}\n', b''))
        self.assertLess(time.monotonic() - start, 4)

    def test_real_worker_relays_all_lifecycle_events_through_actual_guard(self):
        shutil.copy2(self.worker, self.worker_path)
        config = Path(__file__).resolve().parents[2] / 'cmd/may/internal/beholdercontext/managed.example.toml'
        self.assertEqual(len(verify_hook_contract(self.guard, config.read_bytes())), 6)

    def test_missing_and_unexecutable_worker(self):
        self.assert_continues()
        self.worker_path.write_bytes(b'invalid executable')
        self.assert_continues()
        self.worker_path.chmod(0o700)
        self.assert_continues()

    def test_exit_two_and_block_output_are_never_forwarded(self):
        for code in ['exit 2', "echo '{\"decision\":\"block\",\"continue\":false}'; exit 0", 'echo private-error >&2; exit 1']:
            with self.subTest(code=code):
                self.worker_script(code)
                self.assert_continues()

    def test_worker_signal_does_not_become_policy_block(self):
        self.worker_script('kill -ABRT $$')
        self.assert_continues()

    def test_worker_timeout_and_unclosed_stdin_are_bounded(self):
        self.worker_script('exec /bin/sleep 30')
        self.assert_continues()
        shutil.copy2(self.worker, self.worker_path)
        proc = subprocess.Popen([str(self.guard)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: proc.kill() if proc.poll() is None else None)
        start = time.monotonic()
        self.assertEqual(proc.wait(timeout=4.5), 0)
        self.assertLess(time.monotonic() - start, 4)
        out, err = proc.communicate()
        self.assertEqual((out, err), (b'{}\n', b''))

    def test_invalid_arguments_and_missing_core_continue(self):
        shutil.copy2(self.worker, self.worker_path)
        self.assert_continues(args=['--undefined-option'])
        self.assert_continues(command=True)

    def test_outer_command_survives_missing_or_wrong_guard(self):
        self.guard.unlink()
        self.assert_continues(command=True)
        self.guard.write_text('#!/bin/sh\necho \'{"decision":"block"}\'\nexit 2\n')
        self.guard.chmod(0o700)
        self.assert_continues(command=True)

    def test_guard_termination_cleans_up_and_continues(self):
        ready = self.root / 'worker-ready'
        self.worker_script('echo $$ > ' + str(ready) + '\nexec /bin/sleep 30')
        proc = subprocess.Popen([str(self.guard)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: proc.kill() if proc.poll() is None else None)
        deadline = time.monotonic() + 2
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready.exists(), 'worker did not start')
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=1)
        self.assertEqual((proc.returncode, out, err), (0, b'{}\n', b''))
        with self.assertRaises(ProcessLookupError):
            os.kill(int(ready.read_text()), 0)

    def test_contract_rejects_an_incorrect_worker_component(self):
        self.worker_script('exit 2')
        self.assert_continues(args=['--core-socket', '/private/tmp/unused.sock'])
        with self.assertRaisesRegex(RuntimeError, 'component identity mismatch'):
            verify_hook_contract(self.guard)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--may', required=True, type=Path)
    args = parser.parse_args()
    MAY_BINARY = args.may.resolve(strict=True)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(GuardTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
