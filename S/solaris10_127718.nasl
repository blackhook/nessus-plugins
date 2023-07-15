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
 script_id(31759);
 script_version("1.18");

 script_name(english: "Solaris 10 (sparc) : 127718-05");
 script_cve_id("CVE-2008-1684");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 127718-05");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: svc.startd and rpc.metad patch.
Date this patch was last updated by Sun : Apr/01/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1019015.1.html");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
 script_cwe_id(59,362);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/04");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 script_summary(english: "Check for patch 127718-05");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");
