#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:011
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(13783);
 script_bugtraq_id(6884, 6946);
 script_version("1.17");
 script_cve_id("CVE-2003-0078");
 
 name["english"] = "SUSE-SA:2003:011: openssl";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:011 (openssl).


OpenSSL is an implementation of the Secure Sockets Layer and Transport
Layer Security protocols and provides strong cryptography for many
applications in a Linux system. It is a default package in all SUSE
products.

A security weakness has been found, known as 'Vaudenay timing attack
on CBC', named after one of the discoverers (Brice Canvel (EPFL), Alain
Hiltgen (UBS), Serge Vaudenay (EPFL), and Martin Vuagnoux (EPFL, Ilion)).
The weakness may allow an attacker to obtain a plaintext data block by
observing timing differences in response to two different error cases
(cipher padding errors vs. MAC verification errors).
In order to exploit this vulnerability, the attacker has to meet certain
requirements: The network connection between client and server must be
of high quality to be able to observe timing differences, the attacker
must be able to perform a man-in-the-middle attack, the transactions
must repeatedly contain the same (encrypted) plain text block (such as
a pop password or alike), and decoding failures in the SSL layer must
not be propagated to the application that is using the SSL connection.
These exploitation conditions considerably reduce the security risk
imposed by the vulnerability. However, we recommend to completely
remedy this weakness by installing the update packages for your system
according to the following guidelines. There does not exist any temporary
workaround for this problem other than applying the update packages.


Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_011_openssl.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");




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
if ( rpm_check( reference:"openssl-0.9.6a-78", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6a-78", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6b-154", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6c-83", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6g-55", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"SUSE7.1")
 || rpm_exists(rpm:"openssl-", release:"SUSE7.2")
 || rpm_exists(rpm:"openssl-", release:"SUSE7.3")
 || rpm_exists(rpm:"openssl-", release:"SUSE8.0")
 || rpm_exists(rpm:"openssl-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0078", value:TRUE);
}
