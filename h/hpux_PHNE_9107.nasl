#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(17039);
 script_version("1.6");

 name["english"] = "HP-UX Security patch : PHNE_9107";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing HP-UX Security Patch number PHNE_9107 .
(SYN Flooding Security Vulnerability in HP-UX)" );
 script_set_attribute(attribute:"solution", value:
"ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHNE_9107" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"see_also", value:"HPUX security bulletin 060" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");
 script_end_attributes();

 
 summary["english"] = "Checks for patch PHNE_9107";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
 family["english"] = "HP-UX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");

if ( ! hpux_check_ctx ( ctx:"800:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_9107 PHNE_11531 PHNE_12058 PHNE_12408 PHNE_13287 PHNE_13468 PHNE_14492 PHNE_14271 PHNE_14770 PHNE_15582 PHNE_16210 PHNE_17097 PHNE_17730 PHNE_19116 PHNE_19936 PHNE_20834 PHNE_22507 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NET-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
