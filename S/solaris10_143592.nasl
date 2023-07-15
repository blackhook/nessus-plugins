#%NASL_MIN_LEVEL 70300

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/10/12.

#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(49079);
 script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

 script_name(english:"Solaris 10 (sparc) : 143592-09");
 script_summary(english:"Check for patch 143592-09");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing Sun Security Patch number 143592-09");
 script_set_attribute(attribute:"description", value:
'SunOS 5.10: ipf ipfs ippool patch.
Date this patch was last updated by Sun : Mar/30/11');
 script_set_attribute(attribute:"solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute:"see_also", value:
"https://getupdates.oracle.com/readme/143592-09");
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/03/30");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/02");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
 script_family(english:"Solaris Local Security Checks");
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");
