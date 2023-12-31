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
 script_id(23323);
 script_version("1.19");

 script_name(english: "Solaris 5.8 (sparc) : 110060-22");
 script_cve_id("CVE-2007-0957", "CVE-2007-2798");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 110060-22");
 script_set_attribute(attribute: "description", value:
'SEAM 1.0.1: patch for Solaris 8.
Date this patch was last updated by Sun : Jul/24/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/110060-22");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_cwe_id(119);
 script_set_attribute(attribute: "patch_publication_date", value: "2007/07/24");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("Date: 2018/08/13 14:32:38");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/03");
 script_end_attributes();

 script_summary(english: "Check for patch 110060-22");
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

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110060-22", obsoleted_by:"", package:"SUNWkr5ma", version:"5.8.0,REV=99.12.09.18.58");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110060-22", obsoleted_by:"", package:"SUNWkr5sl", version:"5.8.0,REV=99.12.09.18.58");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"110060-22", obsoleted_by:"", package:"SUNWkr5sv", version:"5.8.0,REV=99.12.09.18.58");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
