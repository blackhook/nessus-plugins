#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(17988);
 script_cve_id("CVE-2005-1020", "CVE-2005-1021");
 script_bugtraq_id(13042, 13043);
 script_version("1.24");

 script_name(english:"Cisco IOS Secure Shell Server TACACS+ Multiple DoS (CSCed65778, CSCed65285)"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
"The remote version of IOS has the ability to enable an SSH server to let
the administrators connect to the remote device.

There is an implementation flaw in the remote version of this software
which may allow an attacker to cause a resource starvation on the remote
device, thus preventing it from routing properly." );
 script_set_attribute(attribute:"solution", value:
"http://www.nessus.org/u?6f0e5315" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(287, 399);

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


# 12.0 
if ( check_release(version:version, 
		   patched:make_list("12.0(26)S5", "12.0(27)S4", "12.0(28)S2", "12.0(30)S"),
		   newest:"12.0(30)S") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.0(30)SX"),
		   newest:"12.0(30)SX") ) vuln ++;


if ( deprecated_version(version, "12.1AX", "12.1AZ", "12.1DB", "12.1DC", "12.1EC","12.1EU", "12.1EW", "12.1EX", "12.1T", "12.1XD", "12.1XE", "12.1XF", "12.1XG", "12.1XH", " 12.1XI", "12.1XL", "12.1XM,", "12.1XP", "12.1XQ", "12.1XR", "12.1XT", "12.1XU", "12.1XV", "12.1YA", "12.1YB", "12.1YC", "12.1YD", "12.1YE", "12.1YF", "12.1YH", "12.1YI") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(23)E"),
		   newest:"12.1(23)E") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(22)EA1"),
		   newest:"12.1(22)EA1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(23)EB"),
		   newest:"12.1(23)EB") ) vuln ++;


if ( deprecated_version(version, "12.2B", "12.2DD", "12.2DX", "12.2SU", "12.2SY", "12.2SX", "12.2XA", "12.2XC", "12.2XF", "12.2XN", "12.2XS", "12.2YE", "12.2YK", "12.2YO", "12.2YX", "12.2YZ", "12.2ZA") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(26)"),
		   newest:"12.2(26)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(20)EU"),
		   newest:"12.2(20)EU") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(40)EX1"),
		   newest:"12.2(40)EX1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)EW2", "12.2(25)EW"),
		   newest:"12.2(25)EW") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(14)S13", "12.2(18)S7", "12.2(20)S7", "12.2(25)S"),
		   newest:"12.2(25)S") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(20)SE4", "12.2(25)SE"),
		   newest:"12.2(25)SE") ) vuln ++;


if ( "SEA" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(25)SEA"),
		   newest:"12.2(25)SEA") ) vuln ++;

if ( "SEB" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(25)SEB"),
		   newest:"12.2(25)SEB") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(24)SV"),
		   newest:"12.2(24)SV") ) vuln ++;

if ( "SXB" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(17d)SXB"),
		   newest:"12.2(17d)SXB") ) vuln ++;

if ( "SXD" >< version &&
     check_release(version:version, 
		   patched:make_list("12.2(18)SXD"),
		   newest:"12.2(18)SXD") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(13)T"),
		   newest:"12.2(13)T") ) vuln ++;



if ( deprecated_version(version, "12.3XD", "12.3XE", "12.3XF", "12.3XG", "12.3XH", "12.3XJ", "12.3XK") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(4)T11", "12.3(7)T7", "12.3(8)T"),
		   newest:"12.3(8)T") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)XI3"),
		   newest:"12.3(7)XI3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)XL"),
		   newest:"12.3(11)XL") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)XM"),
		   newest:"12.3(7)XM") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(4)XQ1"),
		   newest:"12.3(4)XQ1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)XR"),
		   newest:"12.3(7)XR") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)XS"),
		   newest:"12.3(7)XS") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)XU"),
		   newest:"12.3(8)XU") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)XW"),
		   newest:"12.3(8)XW") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)XX"),
		   newest:"12.3(8)XX") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)XY"),
		   newest:"12.3(8)XY") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YA"),
		   newest:"12.3(8)YA") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YD"),
		   newest:"12.3(8)YD") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YF"),
		   newest:"12.3(11)YF") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YG"),
		   newest:"12.3(8)YG") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YH"),
		   newest:"12.3(8)YH") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YJ"),
		   newest:"12.3(11)YJ") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(11)YK"),
		   newest:"12.3(11)YK") ) vuln ++;

if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 )  display("IOS version ", version, " identified as vulnerable by multiple checks\n");

