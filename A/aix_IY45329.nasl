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
 script_id(14414);
 script_version("1.12");
 script_cve_id("CVE-2003-1018");
 script_bugtraq_id(9254);
 name["english"] = "AIX 5.2 : IY45329";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing AIX Critical Security Patch number IY45329
(SECURITY: Format string vulnerability in /usr/bin/enq and).

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://www-912.ibm.com/eserver/support/fixes/" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");
 script_end_attributes();

 
 summary["english"] = "Check for patch IY45329"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");

 if( aix_check_patch(release:"5.2", patch:"IY45329", package:"bos.rte.printers.5.2.0.11") < 0 ) 
   security_hole();
