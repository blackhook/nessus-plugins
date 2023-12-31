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
 script_id(23307);
 script_version("1.12");

 script_name(english: "Solaris 5.8 (sparc) : 109210-19");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 109210-19");
 script_set_attribute(attribute: "description", value:
'Sun Cluster 2.2: Framework/Comm Patch.
Date this patch was last updated by Sun : Feb/13/04');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/109210-19");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute: "patch_publication_date", value: "2004/02/13");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("Date: 2018/07/20  0:18:53");
 script_end_attributes();

 script_summary(english: "Check for patch 109210-19");
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

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWccd", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWcmm", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWcsnmp", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWff", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWffx", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWmond", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWmondx", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWpnm", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsc", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsccf", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsci", version:"2.2,REV=2000.02.29.15.49");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWscid", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWscins", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsclb", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsclbx", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsma", version:"2.2,REV=2000.03.14.18.21");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
