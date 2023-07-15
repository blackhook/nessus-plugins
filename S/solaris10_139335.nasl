#%NASL_MIN_LEVEL 70300

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/09/17.

#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(36623);
 script_version("1.8");

 script_name(english: "Solaris 5.10 (sparc) : 139335-01");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 139335-01");
 script_set_attribute(attribute: "description", value:
'StarOffice 9 (Solaris): Update 1.
Date this patch was last updated by Sun : Feb/05/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/139335-01");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 script_summary(english: "Check for patch 139335-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");
