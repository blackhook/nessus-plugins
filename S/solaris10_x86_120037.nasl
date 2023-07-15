#%NASL_MIN_LEVEL 70300

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/10/24.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(24384);
 script_version("1.26");

 script_name(english: "Solaris 10 (x86) : 120037-22");
 script_cve_id("CVE-2007-2798");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120037-22");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: libc nss ldap PAM zfs patc.
Date this patch was last updated by Sun : Jul/17/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000466.1.html");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/26");
 script_end_attributes();

 script_summary(english: "Check for patch 120037-22");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");
