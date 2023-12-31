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
 script_id(42333);
 script_version("1.10");

 script_name(english: "Solaris 8 (x86) : 142295-01");
 script_cve_id("CVE-2009-3183");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 142295-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8_x86: whodo w uptime patch.
Date this patch was last updated by Sun : Oct/30/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1020866.1.html");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/11/02");
 script_cvs_date("Date: 2018/08/13 14:32:38");
 script_end_attributes();

 script_summary(english: "Check for patch 142295-01");
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

e +=  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"142295-01", obsoleted_by:"", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.17");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
