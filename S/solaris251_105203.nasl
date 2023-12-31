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
 script_id(12716);
 script_version ("1.16");
 name["english"] = "Solaris 2.5.1 (sparc) : 105203-07";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 105203-07
(CDE 1.1: dtmail patch).

Date this patch was last updated by Sun : Thu Nov 19 17:00:00 MST 1998

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/105203-07" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_end_attributes();

 
 summary["english"] = "Check for patch 105203-07"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"105203-07", obsoleted_by:"", package:"SUNWdtdst", version:"1.1,REV=10.97.06.18");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"105203-07", obsoleted_by:"", package:"SUNWdthev", version:"1.1,REV=10.97.06.18");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"105203-07", obsoleted_by:"", package:"SUNWdtma", version:"1.1,REV=10.97.06.18");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
