#%NASL_MIN_LEVEL 999999

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
include("compat.inc");

if(description)
{
 script_id(37283);
 script_version("1.6");

 script_name(english: "Solaris 5.4 (x86) : 105188-18");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 105188-18");
 script_set_attribute(attribute: "description", value:
'SunLink X25 9.1 patch_x86.
Date this patch was last updated by Sun : Jan/13/04');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/105188-18");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute: "patch_publication_date", value: "2004/01/13");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_cvs_date("Date: 2018/07/20  0:18:53");
 script_end_attributes();

 script_summary(english: "Check for patch 105188-18");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.4_x86", arch:"i386", patch:"105188-18", obsoleted_by:"", package:"SUNWexpx", version:"9.1,PATCH=18");
e +=  solaris_check_patch(release:"5.4_x86", arch:"i386", patch:"105188-18", obsoleted_by:"", package:"SUNWllc2a", version:"9.1,PATCH=18");
e +=  solaris_check_patch(release:"5.4_x86", arch:"i386", patch:"105188-18", obsoleted_by:"", package:"SUNWx25a", version:"9.1,PATCH=18");
e +=  solaris_check_patch(release:"5.4_x86", arch:"i386", patch:"105188-18", obsoleted_by:"", package:"SUNWx25b", version:"9.1,PATCH=18");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
