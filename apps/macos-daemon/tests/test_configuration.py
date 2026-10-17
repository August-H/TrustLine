import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trustline import __main__ as configuration


class ApiKeyConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.env_file = Path(self.directory.name) / "service/.env"
        self.env_file.parent.mkdir()
        self.env_file.write_text('TYPESAFE_API_KEY="test-${literal}-key"\nUNRELATED=value\n')
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.location = patch.object(configuration, "ENV_FILE", self.env_file)
        self.location.start()
        self.addCleanup(self.location.stop)

    def test_dotenv_key_is_literal_and_independent_of_working_directory(self):
        previous = Path.cwd()
        try:
            os.chdir(self.directory.name)
            with patch.object(configuration.subprocess, "run") as keychain:
                self.assertEqual(configuration.api_key(), "test-${literal}-key")
                keychain.assert_not_called()
            self.assertNotIn("UNRELATED", os.environ)
        finally:
            os.chdir(previous)

    def test_existing_environment_key_takes_precedence(self):
        os.environ["TYPESAFE_API_KEY"] = "environment-key"
        self.assertEqual(configuration.api_key(), "environment-key")

    def test_empty_or_missing_dotenv_keeps_keychain_fallback(self):
        for exists in [True, False]:
            if exists:
                self.env_file.write_text("TYPESAFE_API_KEY=\n")
            else:
                self.env_file.unlink()
            with patch.object(configuration.sys, "platform", "darwin"), \
                    patch.object(configuration.subprocess, "run", return_value=Mock(
                        returncode=0, stdout="keychain-key\n")) as keychain:
                self.assertEqual(configuration.api_key(), "keychain-key")
                keychain.assert_called_once()
