package Google::API::AdminSDK;
use strict;
use warnings;
use LWP::UserAgent;
use URI::Escape;
use JSON "decode_json", "encode_json";

our $VERSION = 0.001;

my $TOKEN_URL = 'https://accounts.google.com/o/oauth2/token';

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

sub request
{
	my $self = shift;
	my ($req) = @_;

	my $access_token = $self->get_access_token();
	$req->header("Authorization", "Bearer $access_token");

	my $resp = $self->http->request($req);
	$resp->is_success
		or die "Error: ".$resp->status_line."\n";
	my $resp_obj = decode_json($resp->content);
	return $resp_obj;
}

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

1;
