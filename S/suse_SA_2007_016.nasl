#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2007:016
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(25406);
 script_version("1.10");
 
 name["english"] = "SUSE-SA:2007:016: samba";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2007:016 (samba)." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2007_16_samba.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/04");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the samba package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"samba-3.0.20b-3.8", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.13-1.6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
