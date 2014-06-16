communigate-domainkeys-dkim
===========================

DKIM/DomainKeys signer for CommuniGate CGP free (implemented as a Content-Filtering script)

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
      ("Header Field", "is not", "Dkim-Signature:*"),
      ("Any Route", is, "SMTP**")
    ),
    ((ExternalFilter, SIGN), ("Stop Processing"))
  )
)
