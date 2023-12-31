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
 script_id(23250);
 script_version("1.16");

 script_name(english: "Solaris 5.7 (sparc) : 113136-06");
 script_cve_id("CVE-2006-0408", "CVE-2006-1506");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 113136-06");
 script_set_attribute(attribute: "description", value:
'Sun Grid Engine 5.3: maintenance/security patch.
Date this patch was last updated by Sun : Jan/20/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/113136-06");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute: "patch_publication_date", value: "2006/01/20");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("Date: 2018/08/13 14:32:38");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/24");
 script_end_attributes();

 script_summary(english: "Check for patch 113136-06");
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

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"113136-06", obsoleted_by:"", package:"SDRMsp32", version:"5.3,REV=2002.03.27.15.30");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
