#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated and is no longer used 
# after a revamping of the Slackware generator.
#
# Disabled on 2011/05/27. 
#
# This script was automatically generated from a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(18695);
script_version("1.9");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update." );
 script_set_attribute(attribute:"description", value:
"An exploitable overflow has been found in the address handling code of the 
mutt mail client version 1.2.5i supplied with Slackware 8.0.  A new
mutt-1.2.5.1 has been released which addresses this problem, and packages
are now available for Slackware 8.0 and -current.

We urge all Slackware users to upgrade to this new version of mutt as soon
as possible." );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/13");
script_end_attributes();


script_summary("SSA mutt remote exploit patched");
name["english"] = "SSA-18695 mutt remote exploit patched";
script_name(english:name["english"]);exit(0);
}

exit(0);

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "-current", pkgname: "mutt", pkgver: "1.2.5.1", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mutt is vulnerable in Slackware -current
Upgrade to mutt-1.2.5.1-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: desc); }
