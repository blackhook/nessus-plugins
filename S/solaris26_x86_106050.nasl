#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/10/24.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(13010);
 script_version("1.19");

 script_name(english: "Solaris 2.6 (x86) : 106050-05");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 106050-05");
 script_set_attribute(attribute: "description", value:
'SunOS 5.6_x86: /usr/sbin/in.telnetd patch.
Date this patch was last updated by Sun : May/07/03');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000108.1.html");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_cvs_date("Date: 2018/07/20  0:18:53");
 script_end_attributes();

 script_summary(english: "Check for patch 106050-05");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.6_x86", arch:"i386", patch:"106050-05", obsoleted_by:"", package:"SUNWcsu", version:"11.6.0,REV=1997.07.16.00.21");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
