package Google::API::AdminSDK;
use strict;
use warnings;
use LWP::UserAgent;
use URI::Escape;
use JSON "decode_json", "encode_json";

our $VERSION = 0.001;

my $TOKEN_URL = 'https://accounts.google.com/o/oauth2/token';

=head1 NAME

Google::API::AdminSDK - client library for Google's Admin SDK

=head1 SYNOPSIS

 use Google::API::AdminSDK;
 my $google = Google::API::AdminSDK->new(
        ClientId => '123456789-1a2b3c4d5e.apps.googleusercontent.com',
        ClientSecret => 'XYZsecret123',
        RefreshToken => $token_string,
        );

 my $user_data = $google->get_user(
        userKey => 'user1@example.com',
        );

=head1 CONSTRUCTOR

=head2 new()

 my $google = Google::API::AdminSDK->new(
        ClientId => '123456789-1a2b3c4d5e.apps.googleusercontent.com',
        ClientSecret => 'XYZsecret123',
        RefreshToken => $token_string,
        );

Constructs a new API object. ClientId and ClientSecret are unique to
your app and are issued to you by Google through the
Google Developers Console (you must find the "Create new Client ID"
function, and select "Installed application" as the application type).
These strings simply identify your application to Google and are not
associated with authorization.

RefreshToken is a string that gives you access to a specific Google Apps
account or domain. See the AUTHORIZATION section below for more information.

=cut

sub new
{
	my $class = shift;
	my %args = @_;

	if ($args{KeyFile} && !$args{Key}) {
		$args{Key} = slurp_file($args{KeyFile});
	}

	unless (($args{Key} && $args{ServiceAddr} && $args{AdminAcct}) ||
		($args{ClientId} && $args{ClientSecret})) {
		die "missing one or more arguments to new()\n";
	}

	if ($args{AuthTokenCache}) {
		if (-e $args{AuthTokenCache}) {
			$args{access_token} = slurp_file($args{AuthTokenCache});
		}
	}

	return bless \%args, $class;
}

sub slurp_file
{
	my ($file) = @_;

	open my $fh, "<", $file
		or die "$file: $!\n";
	local $/;
	my $data = <$fh>;
	close $fh
		or die "$file: $!\n";

	return $data;
}

sub get_access_token
{
	my $self = shift;

	return $self->{access_token} if defined $self->{access_token};

	my $content = join '&',
		'refresh_token='.uri_escape($self->{RefreshToken}),
		'client_id='.uri_escape($self->{ClientId}),
		'client_secret='.uri_escape($self->{ClientSecret}),
		'grant_type=refresh_token';

	my $req = HTTP::Request->new("POST", $TOKEN_URL);
	$req->header('Content-Type', 'application/x-www-form-urlencoded');
	$req->content($content);

	my $resp = $self->http->request($req);
	$resp->is_success
		or die $resp->status_line;

	my $resp_data = decode_json($resp->content);
	$self->{access_token} = $resp_data->{access_token}
		or die "Error: Auth response does not contain access token.\n";

	if ($self->{AuthTokenCache}) {
		open my $fh, ">", $self->{AuthTokenCache}
			or die "$self->{AuthTokenCache}: $!\n";
		print $fh $self->{access_token};
		close $fh
			or die "$self->{AuthTokenCache}: $!\n";
	}

	return $self->{access_token};
}

sub get_refresh_token
{
	my $self = shift;
	my ($code) = @_;

	my $content = join '&',
		'code='.uri_escape($code),
		'client_id='.uri_escape($self->{ClientId}),
		'client_secret='.uri_escape($self->{ClientSecret}),
		'redirect_uri='.uri_escape('urn:ietf:wg:oauth:2.0:oob'),
		'grant_type=authorization_code';

	my $req = HTTP::Request->new("POST", $TOKEN_URL);
	$req->header('Content-Type', 'application/x-www-form-urlencoded');
	$req->content($content);

	my $resp = $self->http->request($req);
	$resp->is_success
		or die $resp->status_line;

	my $resp_data = decode_json($resp->content);
	$self->{access_token} = $resp_data->{access_token}
		or die "Error: Auth response does not contain access token.\n";

	return $resp_data->{refresh_token};
}

sub http
{
	my $self = shift;
	$self->{http_agent} ||= LWP::UserAgent->new;
	return $self->{http_agent};
}

=head1 METHODS

=head2 request()

 my $data = $google->request($req);

This generic request method adds the necessary OAuth2 access token
to the request, fetching it from the OAuth2 token service if needed.
This method throws an error if the response is not a successful one.
It parses the response as JSON and returns the parsed JSON object.

=cut

sub request
{
	my $self = shift;
	my ($req) = @_;

	my $access_token = $self->get_access_token();
	$req->header("Authorization", "Bearer $access_token");

	my $resp = $self->http->request($req);
	if ($resp->code == 401) {

		undef $self->{access_token};
		$access_token = $self->get_access_token();
		$req->header("Authorization", "Bearer $access_token");
		$resp = $self->http->request($req);
	}

	$resp->is_success
		or die "Error: ".$resp->status_line."\n";
	my $resp_obj = decode_json($resp->content);
	return $resp_obj;
}

=head2 list_users()

 my $users_data = $google->list_users(domain => 'example.com');
 foreach my $user_info (@{$users_data->{users}}) {
     # do something with $user_info
 }

=cut

sub list_users
{
	my $self = shift;
	my (%args) = @_;

	my $url = 'https://www.googleapis.com/admin/directory/v1/users?'
		. join('&', map { "$_=".uri_escape($args{$_}) }
			grep defined($args{$_}), keys %args);
	my $req = HTTP::Request->new("GET", $url);
	return $self->request($req);
}

sub interactively_acquire_refresh_token
{
	my $self = shift;

	use URI::Escape;
	use IO::Handle;

	my $redirect_uri='urn:ietf:wg:oauth:2.0:oob';
	my @scopes = qw(
		https://www.googleapis.com/auth/admin.directory.user
		);

	print "This program will help you acquire a refresh token for use with\n";
	print "the Google Admin SDK. To start, open this URL in your web browser.\n";
	print "\n";

	my $url = 'https://accounts.google.com/o/oauth2/auth?'.join('&',
		'scope='.uri_escape(join(' ',@scopes)),
		'redirect_uri='.uri_escape($redirect_uri),
		'response_type=code',
		'client_id='.uri_escape($self->{ClientId}));
	print "$url\n";
	print "\n";
	print "Sign in to Google using the admin account of your Google Apps domain.\n";
	print "\n";
	print "After you confirm access, enter the access code you are shown:\n";
	print "--> ";
	STDOUT->flush;

	my $code = <STDIN>;
	chomp $code;
	return if not $code;

	my $refresh_token = $self->get_refresh_token($code);
	print "\n";
	print "Success!\n";
	print "Here is your refresh token:\n";
	print "$refresh_token\n";
}

=head1 AUTHORIZATION

Authentication and authorization to the Google API is done through
tokens. Normally tokens are short-lived (one hour), which may be fine
for some use cases, but for automated tasks you probably want something
that is permanent. That is what a "refresh token" is for.

Write the following into a Perl script, substituting your application's
ID and secret in the appropriate places. Then run the script in a Linux
terminal window and follow the instructions. The result will be a
"Refresh Token" that you can put in your application's configuration file
and use whenever your application instantiates the Google::API::AdminSDK
object.

 use Google::API::AdminSDK;
 Google::API::AdminSDK->new(
        ClientId => '123456789-1a2b3c4d5e.apps.googleusercontent.com',
        ClientSecret => 'XYZsecret123',
        )
        ->interactively_acquire_refresh_token;

=head1 COPYRIGHT

Copyright 2014 Jason Long.

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
