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
 script_id(24844);
 script_version("1.17");

 script_name(english: "Solaris 5.10 (sparc) : 119044-04");
 script_cve_id("CVE-2007-1419");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 119044-04");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8 5.9 5.10 5.8_x86 5.9_x86 5.10_x86: JDMK 5.1 patch.
Date this patch was last updated by Sun : Mar/15/11');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/119044-04");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
 script_set_attribute(attribute: "patch_publication_date", value: "2011/03/15");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/03/09");
 script_end_attributes();

 script_summary(english: "Check for patch 119044-04");
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
