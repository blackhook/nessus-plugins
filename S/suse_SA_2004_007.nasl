#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:007
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(13825);
 script_version("1.15");
 script_cve_id("CVE-2004-0079", "CVE-2004-0112");
 
 name["english"] = "SuSE-SA:2004:007: openssl";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2004:007 (openssl).


OpenSSL is an implementation of the Secure Socket Layer (SSL v2/3)
and Transport Layer Security (TLS v1) protocol.
The NISCC informed us about to failure conditions in openssl
that can be triggered to crash applications that use the openssl
library.
The first bug occurs during SSL/TLS handshake in the function
do_change_cipher_spec() due to a NULL pointer assignment.
The second bug affects openssl version 0.9.7* only with Kerberos
cipher suite enabled and can be triggered during SSL/TLS handshake too.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_07_openssl.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the openssl package";
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
if ( rpm_check( reference:"openssl-0.9.6c-87", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6c-87", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6g-114", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6g-114", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-21", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6i-21", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7b-133", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7b-133", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"SUSE8.0")
 || rpm_exists(rpm:"openssl-", release:"SUSE8.1")
 || rpm_exists(rpm:"openssl-", release:"SUSE8.2")
 || rpm_exists(rpm:"openssl-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2004-0079", value:TRUE);
 set_kb_item(name:"CVE-2004-0112", value:TRUE);
}
