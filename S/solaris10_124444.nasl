#%NASL_MIN_LEVEL 70300

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2013/04/30.
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
 script_id(43886);
 script_version("1.18");

 script_name(english: "Solaris 10 (sparc) : 124444-01");
script_cve_id("CVE-2007-5462");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 124444-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: mountd patch.
Date this patch was last updated by Sun : Nov/03/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000452.1.html");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);
 script_set_attribute(attribute: "patch_publication_date", value: "2006/11/03");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 script_summary(english: "Check for patch 124444-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");
