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
 script_id(47667);
 script_version("1.4");
 
 script_name(english: "AIX 530012 : U830290");
 
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing a vendor supplied security patch");
 script_set_attribute(attribute: "description", value:
"The remote host is missing AIX PTF U830290 which is related
to the security of the package bos.rte

You should install this PTF for your system to be up-to-date.");
 script_set_attribute(attribute: "solution", value: 
"Run 'suma -x -a RqType=Security' on the remote system");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/08");
 script_end_attributes();
 
 script_summary(english: "Check for PTF U830290");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
 script_family(english: "AIX Local Security Checks");
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");
if ( ! get_kb_item("Host/AIX/lslpp") ) exit(1, "No patch information");


if ( aix_check_patch(ml:"530012", patch:"U830290", package:"bos.rte.5.3.12.1") < 0 ) 
  security_hole(port:0, extra:aix_report_get());
else exit(0, "Host is not vulnerable");
