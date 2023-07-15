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
 script_id(32498);
 script_version("1.15");

 script_name(english: "Solaris 10 (x86) : 128307-05");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 128307-05");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: devfs patch.
Date this patch was last updated by Sun : Jun/27/08');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/128307-05");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/02");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 script_summary(english: "Check for patch 128307-05");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");
