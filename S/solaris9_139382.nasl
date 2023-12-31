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
 script_id(34435);
 script_version("1.8");

 script_name(english: "Solaris 5.9 (sparc) : 139382-01");
 script_cve_id("CVE-2007-2445");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 139382-01");
 script_set_attribute(attribute: "description", value:
'GNOME 2.0.2: libpng Patch.
Date this patch was last updated by Sun : Oct/03/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/139382-01");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/15");
 script_end_attributes();

 script_summary(english: "Check for patch 139382-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"139382-01", obsoleted_by:"", package:"SUNWpng", version:"11.9.0,REV=2002.03.02.00.35");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
