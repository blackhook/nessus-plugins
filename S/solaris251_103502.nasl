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
 script_id(23005);
 script_version ("1.11");
 name["english"] = "Solaris 2.5.1 (sparc) : 103502-07";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 103502-07
(Solstice AdminSuite 2.2: AdminSuite patch).

Date this patch was last updated by Sun : Tue Aug 19 18:00:00 MDT 1997

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/103502-07" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_end_attributes();

 
 summary["english"] = "Check for patch 103502-07"; 
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

e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"103502-07", obsoleted_by:"", package:"SUNWsacb", version:"6.5,REV=96.04.18.16.51");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"103502-07", obsoleted_by:"", package:"SUNWsadma", version:"6.5,REV=96.04.18.16.51");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"103502-07", obsoleted_by:"", package:"SUNWsadmb", version:"6.5,REV=96.04.18.16.51");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"103502-07", obsoleted_by:"", package:"SUNWsadmc", version:"6.5,REV=96.04.18.16.51");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"103502-07", obsoleted_by:"", package:"SUNWsadmm", version:"6.5,REV=96.04.18.16.51");
e +=  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"103502-07", obsoleted_by:"", package:"SUNWsadmo", version:"6.5,REV=96.04.18.16.51");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
