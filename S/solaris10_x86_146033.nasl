#%NASL_MIN_LEVEL 70300

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2013/05/15.
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
 script_id(57633);
 script_version("1.8");

 script_name(english: "Solaris 10 (x86) : 146033-05");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 146033-05");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: perlbug patch.
Date this patch was last updated by Sun : Sep/28/12');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/146033-05");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute: "patch_publication_date", value: "2012/09/28");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 script_summary(english: "Check for patch 146033-05");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");
