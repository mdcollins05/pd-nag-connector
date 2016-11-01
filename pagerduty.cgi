#!/usr/bin/env perl

use warnings;
use strict;

use CGI;
use JSON;
use LWP::UserAgent;
use Net::DNS;

# =============================================================================

my $CONFIG = {
	# Nagios/Ubuntu defaults
	'command_file' => '/var/lib/nagios3/rw/nagios.cmd', # External commands file
	# Icinga/CentOS defaults
	#'command_file' => '/var/spool/icinga/cmd/icinga.cmd', # External commands file
	# Icinga acknowledgement TTL
	'ack_ttl' => 0, # Time in seconds the acknowledgement in Icinga last before
	                # it times out automatically. 0 means the acknowledgement
	                # never expires. If you're using Nagios this MUST be 0.
	#
	# PagerDuty Webhook source, for validation of the incoming connection
	# https://support.pagerduty.com/hc/en-us/articles/204923760
	'webhook_hostname' => 'webhooks.pagerduty.com'
};

# =============================================================================

sub ackHost {
	my ($time, $host, $author, $comment, $sticky, $notify, $persistent) = @_;

	# Open the external commands file
	if (! open (NAGIOS, '>>', $CONFIG->{'command_file'})) {
		# Well shizzle
		return (undef, $!);
	}

	# Success! Write the command
	if ($CONFIG->{'ack_ttl'} <= 0) {
		printf (NAGIOS "[%u] ACKNOWLEDGE_HOST_PROBLEM;%s;%u;%u;%u;%s;%s\n", $time, $host, $sticky, $notify, $persistent, $author, $comment);

	} else {
		printf (NAGIOS "[%u] ACKNOWLEDGE_HOST_PROBLEM_EXPIRE;%s;%u;%u;%u;%u;%s;%s\n", $time, $host, $sticky, $notify, $persistent, ($time + $CONFIG->{'ack_ttl'}), $author, $comment);
	}
	# Close the file handle
	close (NAGIOS);

	# Return with happiness
	return (1, undef);
}

# =============================================================================

sub deackHost {
	my ($time, $host, $persistent, $author, $comment) = @_;

	# Open the external commands file
	if (! open (NAGIOS, '>>', $CONFIG->{'command_file'})) {
		# Well shizzle
		return (undef, $!);
	}

	# Success! Write the command
	printf (NAGIOS "[%u] ADD_HOST_COMMENT;%s;%u;%s;%s\n", $time, $host, $persistent, $author, $comment);
	printf (NAGIOS "[%u] REMOVE_HOST_ACKNOWLEDGEMENT;%s\n", $time, $host);
	# Close the file handle
	close (NAGIOS);

	# Return with happiness
	return (1, undef);
}

# =============================================================================

sub ackService {
	my ($time, $host, $service, $author, $comment, $sticky, $notify, $persistent) = @_;

	# Open the external commands file
	if (! open (NAGIOS, '>>', $CONFIG->{'command_file'})) {
		# Well shizzle
		return (undef, $!);
	}

	# Success! Write the command
	if ($CONFIG->{'ack_ttl'} <= 0) {
		printf (NAGIOS "[%u] ACKNOWLEDGE_SVC_PROBLEM;%s;%s;%u;%u;%u;%s;%s\n", $time, $host, $service, $sticky, $notify, $persistent, $author, $comment);
		
	} else {
		printf (NAGIOS "[%u] ACKNOWLEDGE_SVC_PROBLEM_EXPIRE;%s;%s;%u;%u;%u;%u;%s;%s\n", $time, $host, $service, $sticky, $notify, $persistent, ($time + $CONFIG->{'ack_ttl'}), $author, $comment);
	}

	# Close the file handle
	close (NAGIOS);

	# Return with happiness
	return (1, undef);
}

# =============================================================================

sub deackService {
	my ($time, $host, $service, $persistent, $author, $comment) = @_;

	# Open the external commands file
	if (! open (NAGIOS, '>>', $CONFIG->{'command_file'})) {
		# Well shizzle
		return (undef, $!);
	}

	# Success! Write the command
	printf (NAGIOS "[%u] ADD_SVC_COMMENT;%s;%s;%u;%s;%s\n", $time, $host, $service, $persistent, $author, $comment);
	printf (NAGIOS "[%u] REMOVE_SVC_ACKNOWLEDGEMENT;%s;%s\n", $time, $host, $service);
	# Close the file handle
	close (NAGIOS);

	# Return with happiness
	return (1, undef);
}

# =============================================================================

sub commentHost {
	my ($time, $host, $persistent, $author, $comment) = @_;

	# Open the external commands file
	if (! open (NAGIOS, '>>', $CONFIG->{'command_file'})) {
		# Well shizzle
		return (undef, $!);
	}

	# Success! Write the command
	printf (NAGIOS "[%u] ADD_HOST_COMMENT;%s;%u;%s;%s\n", $time, $host, $persistent, $author, $comment);
	# Close the file handle
	close (NAGIOS);

	# Return with happiness
	return (1, undef);
}

# =============================================================================

sub commentService {
	my ($time, $host, $service, $persistent, $author, $comment) = @_;

	# Open the external commands file
	if (! open (NAGIOS, '>>', $CONFIG->{'command_file'})) {
		# Well shizzle
		return (undef, $!);
	}

	# Success! Write the command
	printf (NAGIOS "[%u] ADD_SVC_COMMENT;%s;%s;%u;%s;%s\n", $time, $host, $service, $persistent, $author, $comment);
	# Close the file handle
	close (NAGIOS);

	# Return with happiness
	return (1, undef);
}

# =============================================================================

my ($TIME, $QUERY, $POST, $JSON);

$TIME = time ();

my $REMOTE_ADDR = "";
if ( exists $ENV{'REMOTE_ADDR'} ) {
	if ( $ENV{'REMOTE_ADDR'} =~ m/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/ ) {
		$REMOTE_ADDR = $1 ;
	}
}

if ( $REMOTE_ADDR ) {	# If we didn't get any value at all, we'll still try processing the POST.
	my $foundIt = 0 ;
	my $res   = Net::DNS::Resolver->new ;
	my $reply = $res->search( $CONFIG->{'webhook_hostname'} ) ;
	if ( $reply ) {
		foreach my $rr ( $reply->answer ) {
			next unless $rr->type eq "A" ;
			if ( $rr->address eq $REMOTE_ADDR ) {
				$foundIt = 1 ;
				last ;
			}
		}
	}
	if ( $foundIt != 1 ) {
		print "Status: 403 Request from unauthorized IP address $REMOTE_ADDR\n\n403 Request from unauthorized IP address $REMOTE_ADDR\n" ;
		exit( 0 ) ;
	}
}


$QUERY = CGI->new ();

if (! defined ($POST = $QUERY->param ('POSTDATA'))) {
	print ("Status: 400 Requests must be POSTs\n\n400 Requests must be POSTs\n");
	exit (0);
}

if (! defined ($JSON = JSON->new ()->utf8 ()->decode ($POST))) {
	print ("Status: 400 Request payload must be JSON blob\n\n400 Request payload must JSON blob\n");
	exit (0);
}

if ((ref ($JSON) ne 'HASH') || ! defined ($JSON->{'messages'}) || (ref ($JSON->{'messages'}) ne 'ARRAY')) {
	print ("Status: 400 JSON blob does not match the expected format\n\n400 JSON blob does not match expected format\n");
	exit (0);
}

my ($message, $return);
$return = {
	'status' => 'okay',
	'messages' => {}
};

MESSAGE: foreach $message (@{$JSON->{'messages'}}) {
	my ($hostservice, $status, $error, $last_status_change_by, $pd_service, $assigned_to_user, $last_status_change_on, $html_url_incident );
	my $author = 'PagerDuty System' ;
	my $comment = 'Acknowledged via PagerDuty - no specific comment data available' ;

	if ((ref ($message) ne 'HASH') || ! defined ($message->{'type'})) {
		next MESSAGE;
	}

	$hostservice = $message->{'data'}->{'incident'}->{'trigger_summary_data'};

	if (! defined ($hostservice)) {
		next MESSAGE;
	}

	# If we get a "last changed by" object or a "service" object, use it to customize the Author
	if ( defined( $last_status_change_by = $message->{'data'}->{'incident'}->{'last_status_change_by'} ) ) {
		$author = "<a href='" . $last_status_change_by->{ 'html_url' } . "' target='_new' >" . $last_status_change_by->{ 'name' } . "</a> " . $last_status_change_by->{ 'email' } ;
	} elsif ( defined( $pd_service = $message->{'data'}->{'incident'}->{'service'} ) ) {
		$author = "<a href='" . $pd_service->{ 'html_url' } . "' target='_new' >" . $pd_service->{ 'name' } . "</a> " ;
	}

	# Did we get a last changed date?
	if ( defined( $last_status_change_on = $message->{'data'}->{'incident'}->{'last_status_change_on'} ) ) {
		$last_status_change_on .= " " ;		# If we got the date, add a space to delimit what's coming up next
	} else {
		$last_status_change_on = "" ;		# If there's no date, init to null so we can add on
	}

	# Set up a new custom default for the Comment. It may be modifed later depending on the incident type.
	if ( defined( $html_url_incident = $message->{'data'}->{'incident'}->{'html_url'} ) ) {
		$comment = "Acknowledged via PagerDuty: " . $last_status_change_on . "<a href='" . $html_url_incident . "' target='_new' >" . $html_url_incident . " </a>" ;
	}
	if ( defined( $assigned_to_user = $message->{'data'}->{'incident'}->{'assigned_to_user'} ) ) {
		$comment .= " currently assigned to <a href='" . $assigned_to_user->{ 'html_url' } . "' target='_new' >" . $assigned_to_user->{ 'name' } . "</a> " . $assigned_to_user->{ 'email' } ;
	}

	if ($message->{'type'} eq 'incident.acknowledge') {

		if ($hostservice->{'SERVICEDESC'} eq "") {
			($status, $error) = ackHost ($TIME, $hostservice->{'HOSTNAME'}, $author, $comment, 2, 1, 0);

		} else {
			($status, $error) = ackService ($TIME, $hostservice->{'HOSTNAME'}, $hostservice->{'SERVICEDESC'}, $author, $comment, 2, 1, 0);
		}

		$return->{'messages'}{$message->{'id'}} = {
			'status' => ($status ? 'okay' : 'fail'),
			'message' => ($error ? $error : undef)
		};

	} elsif ($message->{'type'} eq 'incident.unacknowledge' || $message->{'type'} eq 'incident.assign' || $message->{'type'} eq 'incident.escalate' || $message->{'type'} eq 'incident.delegate' ) {

		if ( $message->{'type'} eq 'incident.unacknowledge' ) {
			$comment =~ s/Acknowledged via/Acknowledgement removed due to timeout by/ ;
		} elsif ( $message->{'type'} eq 'incident.assign' ) {
			$comment =~ s/Acknowledged/Acknowledgement removed due to reassignment/ ;
		} elsif ( $message->{'type'} eq 'incident.escalate' ) {
			$comment =~ s/Acknowledged/Acknowledgement removed due to escalation/ ;
		} elsif ( $message->{'type'} eq 'incident.delegate' ) {
			$comment =~ s/Acknowledged/Acknowledgement removed due to delegation/ ;
		}
		
		if (! defined ($hostservice->{'SERVICEDESC'})) {
			($status, $error) = deackHost ($TIME, $hostservice->{'HOSTNAME'}, 0, $author, $comment );

		} else {
			($status, $error) = deackService ($TIME, $hostservice->{'HOSTNAME'}, $hostservice->{'SERVICEDESC'}, 0, $author, $comment );
		}

		$return->{'messages'}->{$message->{'id'}} = {
			'status' => ($status ? 'okay' : 'fail'),
			'message' => ($error ? $error : undef)
		};
		$return->{'status'} = ($status eq 'okay' ? $return->{'status'} : 'fail');

	} elsif ($message->{'type'} eq 'incident.resolve' || $message->{'type'} eq 'incident.trigger' ) {

		if ( $message->{'type'} eq 'incident.resolve' ) {
			$comment =~ s/Acknowledged/Resolved/ ;
		} elsif ( $message->{'type'} eq 'incident.trigger' ) {
			$comment =~ s/Acknowledged via/Received by/ ;
		}

		if (! defined ($hostservice->{'SERVICEDESC'})) {
			($status, $error) = commentHost ($TIME, $hostservice->{'HOSTNAME'}, 0, $author, $comment );

		} else {
			($status, $error) = commentService ($TIME, $hostservice->{'HOSTNAME'}, $hostservice->{'SERVICEDESC'}, 0, $author, $comment);
		}

		$return->{'messages'}->{$message->{'id'}} = {
			'status' => ($status ? 'okay' : 'fail'),
			'message' => ($error ? $error : undef)
		};
		$return->{'status'} = ($status eq 'okay' ? $return->{'status'} : 'fail');
	}
}

printf ("Status: 200 Okay\nContent-type: application/json\n\n%s\n", JSON->new ()->utf8 ()->encode ($return));
