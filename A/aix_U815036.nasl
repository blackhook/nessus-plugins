#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(32247);
 script_version("1.6");
 
 script_name(english: "AIX 520010 : U815036");
 
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing a vendor supplied security patch");
 script_set_attribute(attribute: "description", value:
"The remote host is missing AIX PTF U815036 which is related
to the security of the package devices.sata.rte

You should install this PTF for your system to be up-to-date.");
 script_set_attribute(attribute: "solution", value: 
"Run 'suma -x -a RqType=Security' on the remote system");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/13");
 script_end_attributes();
 
 script_summary(english: "Check for PTF U815036");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
 script_family(english: "AIX Local Security Checks");
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");
if ( ! get_kb_item("Host/AIX/lslpp") ) exit(1, "No patch information");


if ( aix_check_patch(ml:"520010", patch:"U815036", package:"devices.sata.rte.5.2.0.1") < 0 ) 
  security_hole(port:0, extra:aix_report_get());
else exit(0, "Host is not vulnerable");
