#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:016
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(20082);
 script_version("1.11");
 script_cve_id("CVE-2005-0231", "CVE-2005-0232", "CVE-2005-0233", "CVE-2005-0255");
 
 name["english"] = "SUSE-SA:2005:016: Mozilla Firefox";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:016 (Mozilla Firefox).


This security update for Mozilla Firefox fixes following problems:

- CVE-2005-0231: 'Fire tabbing'
The javascript security manager usually prevents that a javascript:
URL from one host is opened in a window displaying content from
another host. But when the link is dropped to a tab, the security
manager does not kick in.

This can lead to several security problems scaling from stealing
session cookies to the ability to run arbitrary code on the client
system (depending on the displayed site or security settings).

- CVE-2005-0232: 'Fire flashing'

Using plugins like Flash and the -moz-opacity filter it is possible
to display the about:config site in a hidden frame or a new window.

By making the user double-click at a specific screen position
(e.g. using a DHTML game) you can silently toggle the status of
boolean config parameters.

- CVE-2005-0233: 'homograph attacks' / 'IDN cloaking'

Attackers may spoof host names by using translated host name
representation which look exactly the same as the original host,
allowing phishing attacks or similar.

We now show both IDN punycode and visible form of the host name.

- CVE-2005-0255:

Attackers could cause overflows or crashes in low memory situations.

- Added additional Firefox bugfixes from the 1.0.1 release.


Only the listed distributions are affected, others do not ship 
Mozilla Firefox.

Also note that Firefox was called Firebird in SUSE Linux 9.0." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_16_mozilla_firefox.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the Mozilla Firefox package";
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
if ( rpm_check( reference:"MozillaFirebird-1.0.1-2", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.1-9.1", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.1-9.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"Mozilla Firefox-", release:"SUSE9.0")
 || rpm_exists(rpm:"Mozilla Firefox-", release:"SUSE9.1")
 || rpm_exists(rpm:"Mozilla Firefox-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0231", value:TRUE);
 set_kb_item(name:"CVE-2005-0232", value:TRUE);
 set_kb_item(name:"CVE-2005-0233", value:TRUE);
 set_kb_item(name:"CVE-2005-0255", value:TRUE);
}
