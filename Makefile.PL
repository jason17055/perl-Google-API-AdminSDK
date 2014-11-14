use 5.008008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	NAME           => 'Google::API::AdminSDK',
	VERSION_FROM   => 'lib/Google/API/AdminSDK.pm',
	PREREQ_PM      => { # e.g., Module::Name => 1.1
		LWP => 6.000,
		},
	ABSTRACT_FROM  => 'lib/Google/API/AdminSDK.pm',
	AUTHOR         => 'Jason Long <jason@long.name>',
);
