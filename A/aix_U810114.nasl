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
 script_id(28793);
 script_version("1.6");
 name["english"] = "AIX 520009 : U810114";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing AIX PTF U810114 which is related
to the security of the package devices.pci.4f111100.com

You should install this PTF for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"Run 'suma -x -a RqType=Security' on the remote system" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/03");
script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/05");
 script_end_attributes();

 
 summary["english"] = "Check for PTF U810114"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");

if ( aix_check_patch(ml:"520009", patch:"U810114", package:"devices.pci.4f111100.com.5.2.0.96") < 0 ) 
  security_hole(port:0, extra:aix_report_get());
