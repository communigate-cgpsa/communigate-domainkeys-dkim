"""Exercise the real helper with fake signing, without keys, CPAN or network."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "sign.pl"
PERL = os.environ.get("PERL", "perl")
STUB = r'''
package Mail::DKIM::Signer;
sub new { bless {}, shift }
sub PRINT { }
sub CLOSE { }
sub message_sender { bless {}, 'TestSender' }
sub signatures { (bless({kind=>'DKIM'}, 'TestSignature'), bless({kind=>'DomainKey'}, 'TestSignature')) }
package TestSender;
sub address { 'sender@example.org' }
sub host { 'example.org' }
package TestSignature;
sub as_string {
    my $kind = $_[0]->{kind};
    return "$kind-Signature: " . ('x' x 5000) if $ENV{TEST_LONG_SIGNATURE};
    return "$kind-Signature: v=1;\r\n\tb=abc; note=\"quoted\\value\"";
}
1;
'''


class HelperProtocolTest(unittest.TestCase):
    def run_helper(self, to_header="To: visible@example.net\nCc: copied@example.net\n", signed=False, long=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lib = root / "lib" / "Mail" / "DKIM"
            lib.mkdir(parents=True)
            (lib / "Signer.pm").write_text(STUB)
            for name in ("DkSignature", "TextWrap"):
                (lib / (name + ".pm")).write_text("1;\n")
            # The helper imports Pod::Usage but never calls it.
            (root / "lib" / "Pod").mkdir()
            (root / "lib" / "Pod" / "Usage.pm").write_text("1;\n")
            envelope = "P <sender@example.org>\nR <hidden@example.net>\nR <visible@example.net>\n\n"
            message = "From: sender@example.org\n" + to_header + "Subject: test\n"
            if signed:
                message += "DKIM-Signature: existing\n"
            original = (envelope + message + "\nTest body.\n").encode()
            fixture = root / "test.msg"
            fixture.write_bytes(original)
            env = os.environ.copy()
            env.pop("TEST_LONG_SIGNATURE", None)
            if long:
                env["TEST_LONG_SIGNATURE"] = "1"
            result = subprocess.run(
                [PERL, "-I", str(root / "lib"), str(SCRIPT)],
                input="1 INTF 4\n2 FILE test.msg\n3 QUIT\n", text=True,
                capture_output=True, timeout=15, cwd=root, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(fixture.read_bytes(), original)
            self.assertFalse((root / "Submitted").exists())
            self.assertNotIn("DISCARD", result.stdout)
            self.assertIn("1 INTF 4\n", result.stdout)
            return next(line for line in result.stdout.splitlines() if line.startswith("2 "))

    def test_bcc_and_bcc_only_preserve_original_envelope(self):
        for to in ("To: visible@example.net\nCc: copied@example.net\n", "To: undisclosed-recipients:;\n"):
            with self.subTest(to=to):
                response = self.run_helper(to_header=to)
                match = re.fullmatch(r'2 ADDHEADER "((?:[^"\\]|\\.)*)" OK', response)
                self.assertIsNotNone(match, response)
                encoded = match.group(1)
                self.assertNotRegex(encoded, r"[\x00-\x1f]")
                self.assertNotIn("hidden@example.net", encoded)
                escapes = {"e": "\r\n", "t": "\t", '"': '"', "\\": "\\"}
                decoded = re.sub(r"\\(.)", lambda m: escapes[m[1]], encoded)
                expected = '\r\n'.join(
                    kind + '-Signature: v=1;\r\n\tb=abc; note="quoted\\value"'
                    for kind in ("DomainKey", "DKIM")
                )
                self.assertEqual(decoded, expected)
                self.assertLess(len(response.encode()) + 2, 4097)

    def test_already_signed_passes_through(self):
        self.assertEqual(self.run_helper(signed=True), "2 OK")

    def test_oversized_signature_postpones_without_discard(self):
        self.assertEqual(self.run_helper(long=True), '2 REJECTED "DKIM response exceeds helper limit"')


if __name__ == "__main__":
    unittest.main()
