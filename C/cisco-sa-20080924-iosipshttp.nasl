#TRUSTED 3d48da31d2cf84cd56fba7279df00181585432b48f7a9e73342068aa4bf022e8aa95ec6766e3fdb459a432f74117966be34908e6ea07612a0f9fed2c82a12d6a071b27ac737c1c8c8c85a6b7697874aec02946cd79cbcc5be3655df9705b662f8bb6581988bb96c1c88301b95fa334ff7371e6dd027c9e5f258f3b2c7573f4762d58ab02b4d64004070ff2274c0ffcef74170c8884c8bc9276997759df7c0168d46cd1e97ef05038b9ad23fc8512f64effb3b1d187a09e543c3a731f16201f1de68bc003d9d698d3a5683db8f11d43b4289a6acd6baa4f1a4dc0d0cd3c8d92ae376d73428aea8e123f49c27312d1e0fb14b3fd8b1a9305e49ca42594a65577aaec5e400403920f3fc68a504aad1a105cb35c840d7d01c275c86c0106e2f7393fa618cf62ec560d4d19f882f6d376046e368323985f7c4e97092ccd3f39d05afee2da8ee3bdf64a30910628a5997775dd063d24a26641082acc2e16e2d6ce0408063c8d5b08c5e6ff99b121b36c5fc7778ae2b7e5e3c9e2a55ffb260dc39b9bd29d8cab2113106eb1659f37d57cc58c68fe80de21dd0ee6f0c67bedd740c9c2b1bb8613cba1ace98b01db32cf843a0cff745796df4de5fecd57eb659ef9a5f11d2923a42f48453ad287b90eca36b52edb3e9bf30d8abdc2319646a53efd6781f579e2d67714052e59d92058c5203f087366f7ac82bbef53a29a458a01ab4b0176
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a01556.shtml

include("compat.inc");

if (description)
{
 script_id(49019);
 script_version("1.24");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2008-2739");
 script_bugtraq_id(31364);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsq13348");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-iosips");

 script_name(english:"Cisco IOS IPS Denial of Service Vulnerability - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"The Cisco IOS Intrusion Prevention System (IPS) feature contains a
vulnerability in the processing of certain IPS signatures that use the
SERVICE.DNS engine. This vulnerability may cause a router to crash or
hang, resulting in a denial of service condition.

Cisco has released free software updates that address this
vulnerability. There is a workaround for this vulnerability.

Note: This vulnerability is not related in any way to CVE-2008-1447 -
Cache poisoning attacks.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8becf922");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a01556.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39563ad9");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-iosips.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(11)XW8') flag++;
else if (version == '12.4(11)XW7') flag++;
else if (version == '12.4(11)XW6') flag++;
else if (version == '12.4(11)XW5') flag++;
else if (version == '12.4(11)XW4') flag++;
else if (version == '12.4(11)XW3') flag++;
else if (version == '12.4(11)XW2') flag++;
else if (version == '12.4(11)XW1') flag++;
else if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(6)XT2') flag++;
else if (version == '12.4(6)XT1') flag++;
else if (version == '12.4(6)XT') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(15)XF') flag++;
else if (version == '12.4(6)XE3') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(4)XD9') flag++;
else if (version == '12.4(4)XD8') flag++;
else if (version == '12.4(4)XD7') flag++;
else if (version == '12.4(4)XD5') flag++;
else if (version == '12.4(4)XD4') flag++;
else if (version == '12.4(4)XD2') flag++;
else if (version == '12.4(4)XD10') flag++;
else if (version == '12.4(4)XD1') flag++;
else if (version == '12.4(4)XD') flag++;
else if (version == '12.4(4)XC7') flag++;
else if (version == '12.4(4)XC6') flag++;
else if (version == '12.4(4)XC5') flag++;
else if (version == '12.4(4)XC4') flag++;
else if (version == '12.4(4)XC3') flag++;
else if (version == '12.4(4)XC2') flag++;
else if (version == '12.4(4)XC1') flag++;
else if (version == '12.4(4)XC') flag++;
else if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(15)T5') flag++;
else if (version == '12.4(15)T4') flag++;
else if (version == '12.4(15)T3') flag++;
else if (version == '12.4(15)T2') flag++;
else if (version == '12.4(15)T1') flag++;
else if (version == '12.4(15)T') flag++;
else if (version == '12.4(11)T4') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T7') flag++;
else if (version == '12.4(9)T6') flag++;
else if (version == '12.4(9)T5') flag++;
else if (version == '12.4(9)T4') flag++;
else if (version == '12.4(9)T3') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(6)T9') flag++;
else if (version == '12.4(6)T8') flag++;
else if (version == '12.4(6)T7') flag++;
else if (version == '12.4(6)T6') flag++;
else if (version == '12.4(6)T5') flag++;
else if (version == '12.4(6)T4') flag++;
else if (version == '12.4(6)T3') flag++;
else if (version == '12.4(6)T2') flag++;
else if (version == '12.4(6)T11') flag++;
else if (version == '12.4(6)T10') flag++;
else if (version == '12.4(6)T1') flag++;
else if (version == '12.4(6)T') flag++;
else if (version == '12.4(4)T8') flag++;
else if (version == '12.4(4)T7') flag++;
else if (version == '12.4(4)T6') flag++;
else if (version == '12.4(4)T5') flag++;
else if (version == '12.4(4)T4') flag++;
else if (version == '12.4(4)T3') flag++;
else if (version == '12.4(4)T2') flag++;
else if (version == '12.4(4)T1') flag++;
else if (version == '12.4(4)T') flag++;
else if (version == '12.4(2)T6') flag++;
else if (version == '12.4(2)T5') flag++;
else if (version == '12.4(2)T4') flag++;
else if (version == '12.4(2)T3') flag++;
else if (version == '12.4(2)T2') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(16)MR2') flag++;
else if (version == '12.4(16)MR1') flag++;
else if (version == '12.4(19)') flag++;
else if (version == '12.4(18a)') flag++;
else if (version == '12.4(18)') flag++;
else if (version == '12.4(17b)') flag++;
else if (version == '12.4(17a)') flag++;
else if (version == '12.4(17)') flag++;
else if (version == '12.4(16b)') flag++;
else if (version == '12.4(16a)') flag++;
else if (version == '12.4(16)') flag++;
else if (version == '12.4(13f)') flag++;
else if (version == '12.4(13e)') flag++;
else if (version == '12.4(13d)') flag++;
else if (version == '12.4(13c)') flag++;
else if (version == '12.4(13b)') flag++;
else if (version == '12.4(13a)') flag++;
else if (version == '12.4(13)') flag++;
else if (version == '12.4(12c)') flag++;
else if (version == '12.4(12b)') flag++;
else if (version == '12.4(12a)') flag++;
else if (version == '12.4(12)') flag++;
else if (version == '12.4(10c)') flag++;
else if (version == '12.4(10b)') flag++;
else if (version == '12.4(10a)') flag++;
else if (version == '12.4(10)') flag++;
else if (version == '12.4(8d)') flag++;
else if (version == '12.4(8c)') flag++;
else if (version == '12.4(8b)') flag++;
else if (version == '12.4(8a)') flag++;
else if (version == '12.4(8)') flag++;
else if (version == '12.4(7h)') flag++;
else if (version == '12.4(7g)') flag++;
else if (version == '12.4(7f)') flag++;
else if (version == '12.4(7e)') flag++;
else if (version == '12.4(7d)') flag++;
else if (version == '12.4(7c)') flag++;
else if (version == '12.4(7b)') flag++;
else if (version == '12.4(7a)') flag++;
else if (version == '12.4(7)') flag++;
else if (version == '12.4(5c)') flag++;
else if (version == '12.4(5b)') flag++;
else if (version == '12.4(5a)') flag++;
else if (version == '12.4(5)') flag++;
else if (version == '12.4(3j)') flag++;
else if (version == '12.4(3i)') flag++;
else if (version == '12.4(3h)') flag++;
else if (version == '12.4(3g)') flag++;
else if (version == '12.4(3f)') flag++;
else if (version == '12.4(3e)') flag++;
else if (version == '12.4(3d)') flag++;
else if (version == '12.4(3c)') flag++;
else if (version == '12.4(3b)') flag++;
else if (version == '12.4(3a)') flag++;
else if (version == '12.4(3)') flag++;
else if (version == '12.4(1c)') flag++;
else if (version == '12.4(1b)') flag++;
else if (version == '12.4(1a)') flag++;
else if (version == '12.4(1)') flag++;
else if (version == '12.3(8)ZA') flag++;
else if (version == '12.3(11)YZ2') flag++;
else if (version == '12.3(11)YZ1') flag++;
else if (version == '12.3(11)YZ') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS2') flag++;
else if (version == '12.3(11)YS1') flag++;
else if (version == '12.3(11)YS') flag++;
else if (version == '12.3(14)YM9') flag++;
else if (version == '12.3(14)YM8') flag++;
else if (version == '12.3(14)YM7') flag++;
else if (version == '12.3(14)YM6') flag++;
else if (version == '12.3(14)YM5') flag++;
else if (version == '12.3(14)YM4') flag++;
else if (version == '12.3(14)YM3') flag++;
else if (version == '12.3(14)YM2') flag++;
else if (version == '12.3(14)YM12') flag++;
else if (version == '12.3(14)YM11') flag++;
else if (version == '12.3(14)YM10') flag++;
else if (version == '12.3(11)YK3') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(8)YI3') flag++;
else if (version == '12.3(8)YI2') flag++;
else if (version == '12.3(8)YI1') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG6') flag++;
else if (version == '12.3(8)YG5') flag++;
else if (version == '12.3(8)YG4') flag++;
else if (version == '12.3(8)YG3') flag++;
else if (version == '12.3(8)YG2') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XX2d') flag++;
else if (version == '12.3(8)XX1') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(7)XS2') flag++;
else if (version == '12.3(7)XS1') flag++;
else if (version == '12.3(7)XS') flag++;
else if (version == '12.3(7)XR7') flag++;
else if (version == '12.3(7)XR6') flag++;
else if (version == '12.3(7)XR5') flag++;
else if (version == '12.3(7)XR4') flag++;
else if (version == '12.3(7)XR3') flag++;
else if (version == '12.3(7)XR2') flag++;
else if (version == '12.3(7)XR') flag++;
else if (version == '12.3(4)XQ1') flag++;
else if (version == '12.3(4)XQ') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(14)T7') flag++;
else if (version == '12.3(14)T6') flag++;
else if (version == '12.3(14)T5') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;
else if (version == '12.3(11)T9') flag++;
else if (version == '12.3(11)T8') flag++;
else if (version == '12.3(11)T7') flag++;
else if (version == '12.3(11)T6') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T11') flag++;
else if (version == '12.3(11)T10') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.3(8)T9') flag++;
else if (version == '12.3(8)T8') flag++;
else if (version == '12.3(8)T7') flag++;
else if (version == '12.3(8)T6') flag++;
else if (version == '12.3(8)T5') flag++;
else if (version == '12.3(8)T4') flag++;
else if (version == '12.3(8)T3') flag++;
else if (version == '12.3(8)T11') flag++;
else if (version == '12.3(8)T10') flag++;
else if (version == '12.3(8)T1') flag++;
else if (version == '12.3(8)T') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ips_interfaces", "show ip ips interfaces");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"Interface Configuration", multiline:TRUE, string:buf)) && (!preg(pattern:"not configured on any interface", multiline:TRUE, string:buf)) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
