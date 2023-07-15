#%NASL_MIN_LEVEL 70300

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/09/17.

#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(25194);
 script_version("1.13");
 name["english"] = "Solaris 10 (sparc) : 116837-03";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 116837-03
(Sun LDAP C SDK 5.18 patch : SunOS sparc).

Date this patch was last updated by Sun : Fri Feb 06 04:58:02 MST 2009

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"https://getupdates.oracle.com/readme/116837-03" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for patch 116837-03"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");
