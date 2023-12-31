#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0014
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(13778);
 script_version("1.11");
 
 name["english"] = "SUSE-SA:2003:0014: lprold";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:0014 (lprold).


The lprm command of the printing package lprold shipped till SUSE 7.3
contains a buffer overflow. This buffer overflow can be exploited by
a local user, if the printer system is set up correctly, to gain root
privileges.
lprold is installed as default package and has the setuid bit set.

As a temporary workaround you can disable the setuid bit of lprm by
executing the following tasks as root:
- add '/usr/bin/lprm  root.root 755' to /etc/permissions.local
- run 'chkstat -set /etc/permissions.local'
Another way would be to just allow trusted users to run lprm by
executing the following tasks as root:
- add '/usr/bin/lprm  root.trusted 4750' to /etc/permissions.local
- run 'chkstat -set /etc/permissions.local'

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_014_lprold.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the lprold package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"lprold-3.0.48-407", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"lprold-3.0.48-407", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"lprold-3.0.48-408", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
