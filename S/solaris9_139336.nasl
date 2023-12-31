#%NASL_MIN_LEVEL 999999

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
include("compat.inc");

if(description)
{
 script_id(36443);
 script_version("1.4");

 script_name(english: "Solaris 5.9 (sparc) : 139336-01");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 139336-01");
 script_set_attribute(attribute: "description", value:
'StarSuite 9 (Solaris): Update 1.
Date this patch was last updated by Sun : Feb/05/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/139336-01");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_end_attributes();

 script_summary(english: "Check for patch 139336-01");
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

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-base", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-calc", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-core01", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-core02", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-core03", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-core04", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-core05", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-core06", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-en-US-res", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-images", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-ja-res", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-ko-res", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-math", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-onlineupdate", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-ooolinguistic", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-writer", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-zh-CN-res", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"ooobasis30-zh-TW-res", version:"3.0.0,REV=9.2008.09.30");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139336-01", obsoleted_by:"", package:"openofficeorg-ure", version:"1.4.0,REV=9.2008.09.30");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
