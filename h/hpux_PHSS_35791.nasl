#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
 script_id(26877);
 script_version("1.9");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");
 
 script_name(english:"HP-UX Security Patch : PHSS_35791");
 script_summary(english:"Checks for patch in swlist output");

 script_set_attribute(attribute:"synopsis", value: 
"The remote HP-UX host is missing a security-related patch.");
 script_set_attribute(attribute:"description", value:
"X OV OVO8.X PARISC JavaGUI client A.08.24");
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.itrc.hp.com//hp-ux_patches/s700_800/11.X/PHSS_35791");
 script_set_attribute(attribute:"solution", value:"Apply the PHSS_35791 patch.");
 script_set_attribute(attribute:"risk_factor", value:"High");
 
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/03");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
 script_family(english:"HP-UX Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

# this patch is no longer a security fix
exit(0);

