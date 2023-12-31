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
 script_id(13308);
 script_version("1.65");

 script_name(english: "Solaris 8 (sparc) : 108993-67");
 script_cve_id("CVE-2007-0165", "CVE-2008-4619");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 108993-67");
 script_set_attribute(attribute: "description", value:
'SunOS 5.8: LDAP2 client, libc, libthread a.
Date this patch was last updated by Sun : Mar/29/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/108993-67");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_cvs_date("Date: 2018/08/13 14:32:38");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/09");
 script_end_attributes();

 script_summary(english: "Check for patch 108993-67");
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

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWapppr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWapppu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWarc", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWarcx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWatfsr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWatfsu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWcarx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWcarx", version:"11.8.0,REV=2000.01.13.13.40");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWcsl", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWcslx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWcstl", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWcstlx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWcsxu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWdpl", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWdplx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWlldap", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWmdb", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWmdbx", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWnisr", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWnisu", version:"11.8.0,REV=2000.01.08.18.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWpppd", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWpppdr", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWpppdu", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWpppdx", version:"11.8.0,REV=2001.02.21.14.02");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108993-67", obsoleted_by:"128624-01 ", package:"SUNWpppgS", version:"11.8.0,REV=2001.02.21.14.02");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
