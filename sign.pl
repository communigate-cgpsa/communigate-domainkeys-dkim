#!/bin/perl
#
# DKIM/DomainKeys signer for CommuniGate CGP free (implemented as a Content-Filtering script) 
#
# Version: 0.2
# 
# Copyright (c) 2009 Valera V.Kharseko. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#
# Written by vharseko@xxlive.ru.

use Mail::DKIM::Signer;
use Mail::DKIM::DkSignature;
use Mail::DKIM::TextWrap;
use Getopt::Long;
use Pod::Usage;

sub signer_policy {
	my $dkim = shift;

	$dkim->add_signature(Mail::DKIM::Signature->new(
		Algorithm => "rsa-sha256",
		Method    => "simple/relaxed",
		Headers   => $dkim->headers(),
		Domain    => $dkim->message_sender->host,
		Selector  => "default",
		Expiration => time() + 86400,
		Query => "dns/txt",
		Timestamp => time(),
		Identity   => $dkim->message_sender->address
	));
	
	$dkim->add_signature(Mail::DKIM::DkSignature->new(
		Algorithm => "rsa-sha1",
		Method    => "simple",
		Headers   => $dkim->headers,
		Domain    => $dkim->message_sender->host,
		Selector  => "default",
		Expiration => time() + 86400,
		Identity   => $dkim->message_sender->address
	));
	return;
}

sub Log {
	print "* $_[0]\n";
}
$| = 1;
Log "DKIM is running";Log "";
mkdir "Submitted" if ( !-d "Submitted" );
while (<>) {
	my @line = split( / /, $_ );
	chomp( $line[0] );
	print "$line[0] OK\n"     and next if ( $line[1] =~ /^quit$/i );
	print "$line[0] INTF 3\n" and next if ( $line[1] =~ /^intf$/i );
	print "$line[0] OK\n"     and next if ( $line[1] =~ /^key$/i );
	print "$line[0] FAILURE\n" and next if ( $line[1] !~ /^file$/i );    
	$line[2] =~ s|\\|/|g;              
	chomp( $line[2] );

	Log "DKIM process: $line[2]";
	
	if ( !open( MSG, $line[2] ) ) {
		Log "Error: file not found $line[2]";
		print "$line[0] OK\n";
	}
	else {
		my ( $sender, @recipients );
		#CGP headers
		while (1) {
			$line = <MSG>;
			chomp($line);
			last if ( $line eq '');
			if ( $line =~ /^(\w).+<(.+)>/ ) {
				if ( $1 eq 'P' ) {
					$sender = $2;
				}
				else {
					push @recipients, $2;
				}
			}
		}
		#mail headers and body
		my $EntireMessage="";
		my $dkim = new Mail::DKIM::Signer(Policy => \&signer_policy,KeyFile => "/var/CommuniGate/rsa.private");
		while (<MSG>){
			$EntireMessage=$EntireMessage.$_;
			chomp $_;
			s/\015?$/\015\012/s;
			$dkim->PRINT($_);
		}
		close MSG;
		
		if ( $EntireMessage !~ /DKIM-Signature:/i ) {
			$dkim->CLOSE;
			Log "DKIM sign for user=".($dkim->message_sender->address)." domain=".($dkim->message_sender->host);
			
			my $signature_dkim=($dkim->signatures())[0]->as_string;
			$signature_dkim=~s/\r\n/\n/g;
			
			my $signature_dk=($dkim->signatures())[1]->as_string;
			$signature_dk=~s/\r\n/\n/g;
									
			my $alertFileName.="Submitted/A".time().int(rand(10000));
			open(SUBM,">$alertFileName.tmp");
			print SUBM "$signature_dk\n";
			print SUBM "$signature_dkim\n";
			print SUBM $EntireMessage;
			close SUBM;
			rename("$alertFileName.tmp","$alertFileName.sub");
			print "$line[0] DISCARD\n";
		}
		else {
			Log "DKIM skip file: $line[2]";	print "$line[0] OK\n";
		}
	}
	open STDOUT, ">&STDOUT";
}
