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
 script_id(23216);
 script_version("1.12");

 script_name(english: "Solaris 5.7 (sparc) : 107780-02");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 107780-02");
 script_set_attribute(attribute: "description", value:
'Java DMK 3.2 patch.
Date this patch was last updated by Sun : Apr/22/02');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/107780-02");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute: "patch_publication_date", value: "2002/04/22");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("Date: 2018/07/20  0:18:52");
 script_end_attributes();

 script_summary(english: "Check for patch 107780-02");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2018 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107780-02", obsoleted_by:"", package:"SUNWjawag", version:"3.2,PATCH=02");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107780-02", obsoleted_by:"", package:"SUNWjawcl", version:"3.2,PATCH=02");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107780-02", obsoleted_by:"", package:"SUNWjawco", version:"3.2,PATCH=02");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107780-02", obsoleted_by:"", package:"SUNWjawcs", version:"3.2,PATCH=02");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107780-02", obsoleted_by:"", package:"SUNWjawdc", version:"3.2,PATCH=02");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107780-02", obsoleted_by:"", package:"SUNWjawex", version:"3.2,PATCH=02");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"107780-02", obsoleted_by:"", package:"SUNWjawtk", version:"3.2,PATCH=02");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
