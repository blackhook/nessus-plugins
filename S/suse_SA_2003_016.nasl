#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:016
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(13786);
 script_version("1.11");
 
 name["english"] = "SUSE-SA:2003:016: samba, samba-client";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:016 (samba, samba-client).



Sebastian Krahmer, SUSE Security Team, reviewed security-critical
parts of the Samba server within the scope of security audits that
the SUSE Security Team conducts on a regular basis for security-critical
Open Source Software.
Buffer overflows and a chown race condition have been discovered and
fixed during the security audit. The buffer overflow vulnerabilitiy
allows a remote attacker to execute arbitrary commands as root on the
system running samba. In addition to the flaws fixed in the samba
server, some overflow conditions in the samba-client package have
been fixed with the available update packages. It is strongly
recommended to install the update packages on a system where the
samba package is used.

There exists no temporary workaround against this vulnerability other
than shutting down the smbd daemon.

We would like to thank the Samba Team, especially Jeremy Allison, Andrew
Bartlett and Volker Lendecke for their quick response and cooperation.

Please note that the package names for SUSE products vary for different
products. There exist the following pairings:
	server              client
----------------------------
samba               smbclnt
samba               samba-client
samba-classic       samba-classic-client
samba-ldap          samba-ldap-client

To find out which packages are installed on your system, you may run
the following command:

rpm -qa|egrep '(samba|smbclnt)'

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_016_samba.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the samba, samba-client package";
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
if ( rpm_check( reference:"samba-2.0.10-27", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"smbclnt-2.0.10-27", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.0a-48", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"smbclnt-2.2.0a-48", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.1a-213", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.1a-213", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.3a-169", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.3a-169", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.5-160", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.5-160", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
