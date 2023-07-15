#%NASL_MIN_LEVEL 70300

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
include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(40776);
 script_version("1.16");

 script_name(english: "Solaris 10 (sparc) : 141690-02");
 script_xref(name:"IAVT", value:"2009-T-0047-S");
 script_cve_id("CVE-2009-3000");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 141690-02");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: sockfs patch.
Date this patch was last updated by Sun : Aug/25/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/141690-02");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/08/26");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_summary(english: "Check for patch 141690-02");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");
