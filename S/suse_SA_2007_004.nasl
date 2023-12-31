#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2007:004
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(24458);
 script_version("1.10");
 
 name["english"] = "SUSE-SA:2007:004: krb5";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2007:004 (krb5).


Various bugs in the Kerberos5 libraries and tools were fixed which
could be used by remote attackers to crash and potentially execute
code in kadmind.

- CVE-2006-6144 / MITKRB5-SA-2006-002: the RPC library could call an
uninitialized function pointer, which created a security
vulnerability for kadmind.

- CVE-2006-6143 / MITKRB5-SA-2006-003: the GSS-API mechglue layer
could fail to initialize some output pointers, causing callers to
attempt to free uninitialized pointers.  This caused a security
vulnerability in kadmind." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2007_04_krb5.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the krb5 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"krb5-1.4.1-5.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.4.1-5.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-1.4-16.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.4-16.7", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
