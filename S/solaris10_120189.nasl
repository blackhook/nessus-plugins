#%NASL_MIN_LEVEL 70300

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/09/17.

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(22961);
 script_version("1.35");

 script_name(english: "Solaris 5.10 (sparc) : 120189-19");
 script_cve_id("CVE-2006-2198", "CVE-2006-3117", "CVE-2006-5870", "CVE-2007-0002", "CVE-2007-0238", "CVE-2007-0239", "CVE-2007-0245", "CVE-2007-1466", "CVE-2007-2754", "CVE-2007-2834", "CVE-2007-4575");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120189-19");
 script_set_attribute(attribute: "description", value:
'StarSuite 8 (Solaris): Update 14.
Date this patch was last updated by Sun : Sep/09/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/120189-19");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/07/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/30");
 script_end_attributes();

 script_summary(english: "Check for patch 120189-19");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");
