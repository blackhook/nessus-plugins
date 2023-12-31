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
 script_id(13538);
 script_version("1.36");

 script_name(english: "Solaris 9 (sparc) : 113451-17");
 script_xref(name:"IAVT", value:"2009-T-0008-S");
 script_cve_id("CVE-2005-3666", "CVE-2005-3667", "CVE-2005-3668", "CVE-2005-3674", "CVE-2006-2298", "CVE-2006-4339", "CVE-2006-5201", "CVE-2006-7140", "CVE-2007-2989", "CVE-2009-0267");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 113451-17");
 script_set_attribute(attribute: "description", value:
'SunOS 5.9: IKE patch.
Date this patch was last updated by Sun : Aug/09/10');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/113451-17");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/08");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_summary(english: "Check for patch 113451-17");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113451-17", obsoleted_by:"112920-03 ", package:"SUNWcsl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113451-17", obsoleted_by:"112920-03 ", package:"SUNWcsr", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113451-17", obsoleted_by:"112920-03 ", package:"SUNWcstl", version:"11.9.0,REV=2002.04.06.15.27");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"113451-17", obsoleted_by:"112920-03 ", package:"SUNWcsu", version:"11.9.0,REV=2002.04.06.15.27");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
