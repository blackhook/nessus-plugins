#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:020
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(17671);
 script_version("1.11");
 script_cve_id("CVE-2005-0398");
 
 name["english"] = "SUSE-SA:2005:020: ipsec-tools";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:020 (ipsec-tools).


Racoon is a ISAKMP key management daemon used in IPsec setups.

Sebastian Krahmer of the SUSE Security Team audited the daemon and
found that it handles certain ISAKMP messages in a slightly wrong way,
so that remote attackers can crash it via malformed ISAKMP packages.

This update fixes this problem.

This is tracked by the Mitre CVE ID CVE-2005-0398." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_20_ipsec_tools.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/01");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the ipsec-tools package";
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
if ( rpm_check( reference:"ipsec-tools-0.3.3-1.6", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.4rc1-3.2", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"ipsec-tools-", release:"SUSE9.1")
 || rpm_exists(rpm:"ipsec-tools-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0398", value:TRUE);
}
