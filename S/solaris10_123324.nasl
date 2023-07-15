#%NASL_MIN_LEVEL 70300

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
include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(25642);
 script_version("1.25");

 script_name(english: "Solaris 10 (sparc) : 123324-03");
 script_cve_id("CVE-2006-0225", "CVE-2006-4924");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 123324-03");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: sshd patch.
Date this patch was last updated by Sun : Jun/20/07');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000947.1.html");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/02");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/28");
 script_end_attributes();

 script_summary(english: "Check for patch 123324-03");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");
