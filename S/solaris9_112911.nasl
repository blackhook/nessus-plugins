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
 script_id(18073);
 script_version("1.22");

 script_name(english: "Solaris 9 (sparc) : 112911-16");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 112911-16");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9: ifconfig Patch.
Date this patch was last updated by Sun : May/27/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/112911-16");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/17");
 script_end_attributes();

 script_summary(english: "Check for patch 112911-16");
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

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112911-16", obsoleted_by:"120464-01 114344-18 ", package:"SUNWarc", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112911-16", obsoleted_by:"120464-01 114344-18 ", package:"SUNWcsl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112911-16", obsoleted_by:"120464-01 114344-18 ", package:"SUNWcsr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112911-16", obsoleted_by:"120464-01 114344-18 ", package:"SUNWcstl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112911-16", obsoleted_by:"120464-01 114344-18 ", package:"SUNWcsu", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112911-16", obsoleted_by:"120464-01 114344-18 ", package:"SUNWhea", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"112911-16", obsoleted_by:"120464-01 114344-18 ", package:"SUNWroute", version:"11.9.0,REV=2002.04.06.15.27");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
