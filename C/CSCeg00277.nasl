#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17986);
 script_version("1.23");
 script_cve_id("CVE-2005-1058");
 script_bugtraq_id(13033, 13031);

 script_name(english:"Cisco IOS IKE XAUTH ISAKMP IPSec SA Establish Authentication Bypass (CSCeg00277)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote version of IOS contains a feature called 'Easy VPN Server' that
allows the administrator of the remote router to create a lightweight VPN
server.

There is an implementation flaw in the remote version of this software
that could allow an authorized user to complete authentication and access
the VPN remotely." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?d6d9f923" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/06");
 script_cvs_date("Date: 2018/06/27 18:42:25");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}


include('cisco_func.inc');

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);
version = extract_version(os);
if ( ! version ) exit(0);



# 12.2

if ( deprecated_version(version, "12.2B", "12.2BX", "12.2BY", "12.2BZ", "12.2CX", "12.2CY", "12.2SX", "12.2SXA", "12.2SY", "12.2T", "12.2XJ", "12.2XK", "12.2XL", "12.2XM", "12.2XW", "12.2XZ", "12.2YB", "12.2YD", "12.2YF", "12.2YG", "12.2YH", "12.2YJ", "12.2YL", "12.2YM", "12.2YN", "12.2YP", "12.2YQ", "12.2YR", "12.2YT", "12.2YU", "12.2YV", "12.2YW", "12.2YX", "12.2YY", "12.2ZB", "12.2ZC", "12.2ZD", "12.2ZE", "12.2ZF", "12.2ZG", "12.2ZJ", "12.2ZK", "12.2ZN", "12.2P") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(15)BC1f", "12.2(15)BC2e"),
		   newest:"12.2(15)BC2e") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(15)CZ1"),
		   newest:"12.2(15)CZ1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(15)JK2"),
		   newest:"12.2(15)JK2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(14)SU2"),
		   newest:"12.2(14)SU2") ) vuln ++;

if ( "SXB" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(17d)SXB5"),
		   newest:"12.2(17d)SXB5") ) vuln ++;

if ( "SXD" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(18)SXD1"),
		   newest:"12.2(18)SXD1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(4)YA8"),
		   newest:"12.2(4)YA8") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(13)ZH5"),
		   newest:"12.2(13)ZH5") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(15)ZL2"),
		   newest:"12.2(15)ZL2") ) vuln ++;




if ( deprecated_version(version, "12.3BW", "12.3XB", "12.3XF", "12.3XF", "12.3XI", "12.3XJ", "12.3XK", "12.3XM", "12.3XN", "12.3XT", "12.3XW", "12.3XY") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.3(6e)", "12.3(9c)", "12.3(10a)", "12.3(12)"),
		   newest:"12.3(12)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(5a)B3"),
		   newest:"12.3(5a)B3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(9a)BC"),
		   newest:"12.3(9a)BC") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)T9", "12.3(4)T8", "12.3(7)T7", "12.3(8)T5", "12.3(11)T2", "12.3(14)T"),
		   newest:"12.3(14)T") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)XA3"),
		   newest:"12.3(2)XA3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)XC3"),
		   newest:"12.3(2)XC3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(4)XD4"),
		   newest:"12.3(4)XD4") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)XE1"),
		   newest:"12.3(2)XE1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(4)XG2"),
		   newest:"12.3(4)XG2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(4)XQ1"),
		   newest:"12.3(4)XQ1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)XL"),
		   newest:"12.3(11)XL") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.3(7)XR3"),
		   newest:"12.3(7)XR3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)XS2"),
		   newest:"12.3(7)XS2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)XU3"),
		   newest:"12.3(8)XS3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)XX1"),
		   newest:"12.3(8)XX1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YA1"),
		   newest:"12.3(8)YA1") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.3(8)YC1"),
		   newest:"12.3(8)YC1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YD"),
		   newest:"12.3(8)YD") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YF"),
		   newest:"12.3(11)YF") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YG1"),
		   newest:"12.3(8)YG1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YH"),
		   newest:"12.3(8)YH") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YI"),
		   newest:"12.3(8)YI") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YJ"),
		   newest:"12.3(11)YJ") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YK"),
		   newest:"12.3(11)YK") ) vuln ++;

if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 )  display("IOS version ", version, " identified as vulnerable by multiple checks\n");

