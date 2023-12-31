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
 script_id(17135);
 script_version("1.21");

 script_name(english: "Solaris 9 (x86) : 117725-10");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 117725-10");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9_x86: NSPR 4.5.1 / NSS 3.9.5 / JS.
Date this patch was last updated by Sun : Feb/07/05');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/117725-10");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/17");
 script_end_attributes();

 script_summary(english: "Check for patch 117725-10");
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

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117725-10", obsoleted_by:"119212-05 ", package:"SUNWjss", version:"3.1.2.3,REV=2003.03.08.13.04");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117725-10", obsoleted_by:"119212-05 ", package:"SUNWpr", version:"4.1.3,REV=2003.01.09.13.59");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117725-10", obsoleted_by:"119212-05 ", package:"SUNWprd", version:"4.1.6,REV=2003.09.08.11.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117725-10", obsoleted_by:"119212-05 ", package:"SUNWtls", version:"3.3.3,REV=2003.01.09.17.07");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117725-10", obsoleted_by:"119212-05 ", package:"SUNWtlsd", version:"3.3.6,REV=2003.09.08.11.32");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117725-10", obsoleted_by:"119212-05 ", package:"SUNWtlsu", version:"3.3.7,REV=2003.12.01.12.23");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
