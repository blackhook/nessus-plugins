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
 script_id(13236);
 script_version("1.16");

 script_name(english: "Solaris 7 (x86) : 108118-06");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 108118-06");
 script_set_attribute(attribute: "description", value:
'OpenWindows 3.6.1_x86: Font Server patch.
Date this patch was last updated by Sun : Dec/18/02');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/108118-06");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_end_attributes();

 script_summary(english: "Check for patch 108118-06");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"108118-06", obsoleted_by:"", package:"SUNWxwfs", version:"3.7.2100,REV=0.98.08.05");
e +=  solaris_check_patch(release:"5.7_x86", arch:"i386", patch:"108118-06", obsoleted_by:"", package:"SUNWxwfs", version:"3.7.2101,REV=0.98.08.19");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
