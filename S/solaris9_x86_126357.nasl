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
 script_id(30014);
 script_version("1.12");

 script_name(english: "Solaris 5.9 (x86) : 126357-03");
 script_cve_id("CVE-2008-3529", "CVE-2008-4225", "CVE-2008-4226", "CVE-2009-2268", "CVE-2009-2712", "CVE-2009-2713");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 126357-03");
 script_set_attribute(attribute: "description", value:
'Sun Java System Access Manager 7.1 Solaris_x86.
Date this patch was last updated by Sun : Jun/19/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/126357-03");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/18");
 script_cvs_date("Date: 2018/08/22 16:49:14");
 script_end_attributes();

 script_summary(english: "Check for patch 126357-03");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamclnt", version:"7.1,REV=06.11.22.00.23");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamcon", version:"7.1,REV=06.11.22.00.22");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamconsdk", version:"7.1,REV=06.11.22.00.22");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamdistauth", version:"7.1,REV=06.11.22.00.23");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamext", version:"7.1,REV=06.11.20.12.28");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamfcd", version:"7.1,REV=06.11.20.12.28");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWampwd", version:"7.1,REV=06.11.20.12.28");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamrsa", version:"7.1,REV=06.06.28.17.03");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamsam", version:"7.1,REV=06.11.20.12.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamsci", version:"7.1,REV=06.11.20.12.28");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamsdk", version:"7.1,REV=07.01.18.06.04");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamsdkconfig", version:"7.1,REV=06.12.15.12.35");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamsfodb", version:"7.1,REV=06.11.20.12.28");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamsvc", version:"7.1,REV=06.12.19.15.12");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamsvcconfig", version:"7.1,REV=06.11.20.12.28");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"126357-03", obsoleted_by:"", package:"SUNWamutl", version:"7.1,REV=07.01.18.05.38");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
