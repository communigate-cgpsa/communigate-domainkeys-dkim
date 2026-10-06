communigate-domainkeys-dkim
===========================

DKIM/DomainKeys signer for CommuniGate CGP free (implemented as a Content-Filtering script)

Requires External Filter protocol version 4 or later. The signer adds its
signature headers to the original queued message with `ADDHEADER`, preserving
the SMTP envelope, including BCC recipients. It does not resubmit the message
through `Submitted`. Signature headers are escaped using CommuniGate's String
format, and oversized helper responses postpone processing with `REJECTED`.

Protocol regression tests (Python 3 and Perl; no CPAN modules, keys or network
required):

```
python3 tests/test_protocol.py -v
```

Set `PERL` to select a Perl executable. These tests stub only the signing library
and check envelope preservation, BCC privacy, response escaping, already-signed
messages and oversized responses. They do not validate cryptographic signing.

External library
===========================

cpan install Mail::DKIM::Signer

cpan install Mail::DKIM::DkSignature

cpan install Mail::DKIM::TextWrap

cpan install Getopt::Long

cpan install Pod::Usage

How-to config
===========================

/var/CommuniGate/Settings/Main.settings

ExternalFilters = ({Enabled=YES;LogLevel=5;Name=SIGN;ProgramName="/usr/bin/perl /var/CommuniGate/sign.pl";RestartPause=5s;Timeout=10m;});

/var/CommuniGate/Settings/Rules.settings

(
  (
    6,
    "SIGN DKIM",
    (
      (Source, in, "trusted,authenticated"),
      ("Header Field", "is not", "Dkim-Signature:\*"),
      ("Any Route", is, "SMTP\*")
    ),
    ((ExternalFilter, SIGN), ("Stop Processing"))
  )
)
