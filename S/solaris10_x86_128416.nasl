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
 script_id(37825);
 script_version("1.13");

 script_name(english: "Solaris 10 (x86) : 128416-01");
 script_xref(name:"IAVT", value:"2008-T-0029-S");
 script_cve_id("CVE-2008-2946");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 128416-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: usr/lib/dmi/snmpXdmid patc.
Date this patch was last updated by Sun : May/20/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/128416-01");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_summary(english: "Check for patch 128416-01");
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
