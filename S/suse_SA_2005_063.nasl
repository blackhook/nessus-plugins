#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:063
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(20087);
 script_version("1.9");
 
 name["english"] = "SUSE-SA:2005:063: curl, wget";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:063 (curl, wget).


This update fixes a stack-based buffer overflow in the NTLM
authentication code used by the file download tools/libraries curl
and wget that can be triggered by using a long user or domain name
(also works with HTTP redirects).

By exploiting this bug by using a malicious server an attacker may
be able to execute arbitrary code with the privileges of the entity
running the process locally. (CVE-2005-3185)

This affects both curl/libcurl and wget >= 1.10. wget copied the code
from libcurl, making this effectively the same problem." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_63_wget_curl.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the curl, wget package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"compat-curl2-7.11.0-7.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.14.0-2.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.1-2.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.11.0-39.9", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"compat-curl2-7.11.0-4.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.12.0-2.4", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"compat-curl2-7.11.0-6.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.13.0-5.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.10-1.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
