#TRUSTED 9987b1d6088a03317cd7dca0cb8316aa5a6ebb7f360309275be746a94328f676a72f2b75dc121138e9541fd9394e63de2f43f49805d04ea1cb8c83b1ca3847befcfa9cd2128cb1c966d1f5f0796c39628b1cc5a5b403e05453aa0b0a521c01b246cc3d9495f2052b5fc2b8188e91167d71c14ad29ce703c9ee2e746044a78a6f6787e5b563cf34985f1d2d184c75cc1c9a185af6b016b04fc782667e0b6e3cee22bf384dcc37a3be8fb5ebba98d1ecefafd85491e92d0afa287e156a5229b91db35463030dc45f22749c5f94767edc586d5ba78e23092e976369529ccdd499c254f09f961260353fb1b8eab3e3976b30456c57868faf64ef814eff0945728c9ef9e35e2ebe00f7413c70c00053a0b8b08d727e2ff4389f4e5410fa31402552d0ebe7326ebaf0bd36ce176a47c77b7b2fd1ab06ce40242f9348073b0609b35f8ea4eeb118ba62111b94621cfab0b4502e5a866d40b0a579141eb6bc6c33332290c57bbe11279bc2608acc3ecf1181febf0d7738b2c2e3c55789b58b92eec6347708094534e54c3a4e946d8b102d4b36e114c11ddd9c19bc57dd38515fed6279b23e8088b760af54b98684bf131bc131d3f1150dd8acb8be2b4ee4427df0a73c0258f45ce274eeaebb176e96762e31e7b7e1c41a946c539e0e6d7b63793af8f7097c486f716ffb8b0ca50b1c937763650e91521207ead008fe587da3d124cb5575
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080572f55.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48990);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2005-3669");
 script_bugtraq_id(15401);
 script_xref(name:"CERT", value:"226364");
 script_name(english:"Multiple Vulnerabilities Found by PROTOS IPSec Test Suite - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Multiple Cisco products contain vulnerabilities in the processing of
IPSec IKE (Internet Key Exchange) messages. These vulnerabilities were
identified by the University of Oulu Secure Programming Group (OUSPG)
"PROTOS" Test Suite for IPSec and can be repeatedly exploited to
produce a denial of service.
Cisco has made free software available to address this vulnerability
for affected customers. Prior to deploying software, customers should
consult their maintenance provider or check the software for feature
set compatibility and known issues specific to their environment.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a47af26c");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080572f55.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?da9fcb25");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20051114-ipsec.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/11/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCed94829");
 script_xref(name:"CISCO-BUG-ID", value:"CSCei14171");
 script_xref(name:"CISCO-BUG-ID", value:"CSCei15053");
 script_xref(name:"CISCO-BUG-ID", value:"CSCei19275");
 script_xref(name:"CISCO-BUG-ID", value:"CSCei46258");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsb15296");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsc75655");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20051114-ipsec");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(3a)') flag++;
else if (version == '12.4(3)') flag++;
else if (version == '12.4(1b)') flag++;
else if (version == '12.4(1a)') flag++;
else if (version == '12.4(1)') flag++;
else if (version == '12.3(8)ZA') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS1') flag++;
else if (version == '12.3(11)YS') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(8)YI3') flag++;
else if (version == '12.3(8)YI2') flag++;
else if (version == '12.3(8)YI1') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG3') flag++;
else if (version == '12.3(8)YG2') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(11)YF4') flag++;
else if (version == '12.3(11)YF3') flag++;
else if (version == '12.3(11)YF2') flag++;
else if (version == '12.3(11)YF1') flag++;
else if (version == '12.3(11)YF') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XX1') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(8)XW3') flag++;
else if (version == '12.3(8)XW2') flag++;
else if (version == '12.3(8)XW1') flag++;
else if (version == '12.3(8)XW') flag++;
else if (version == '12.3(8)XU5') flag++;
else if (version == '12.3(8)XU4') flag++;
else if (version == '12.3(8)XU3') flag++;
else if (version == '12.3(8)XU2') flag++;
else if (version == '12.3(7)XS2') flag++;
else if (version == '12.3(7)XS1') flag++;
else if (version == '12.3(7)XS') flag++;
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
else if (version == '12.3(4)XK4') flag++;
else if (version == '12.3(4)XK3') flag++;
else if (version == '12.3(4)XK2') flag++;
else if (version == '12.3(4)XK1') flag++;
else if (version == '12.3(4)XK') flag++;
else if (version == '12.3(7)XJ2') flag++;
else if (version == '12.3(7)XJ1') flag++;
else if (version == '12.3(7)XJ') flag++;
else if (version == '12.3(7)XI7') flag++;
else if (version == '12.3(7)XI6') flag++;
else if (version == '12.3(7)XI5') flag++;
else if (version == '12.3(7)XI4') flag++;
else if (version == '12.3(7)XI3') flag++;
else if (version == '12.3(7)XI2a') flag++;
else if (version == '12.3(7)XI2') flag++;
else if (version == '12.3(7)XI1c') flag++;
else if (version == '12.3(7)XI1b') flag++;
else if (version == '12.3(7)XI1') flag++;
else if (version == '12.3(4)XG5') flag++;
else if (version == '12.3(4)XG4') flag++;
else if (version == '12.3(4)XG3') flag++;
else if (version == '12.3(4)XG2') flag++;
else if (version == '12.3(4)XG1') flag++;
else if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(2)XE4') flag++;
else if (version == '12.3(2)XE3') flag++;
else if (version == '12.3(2)XE2') flag++;
else if (version == '12.3(2)XE1') flag++;
else if (version == '12.3(2)XE') flag++;
else if (version == '12.3(4)XD4') flag++;
else if (version == '12.3(4)XD3') flag++;
else if (version == '12.3(4)XD2') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(4)TPC11a') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;
else if (version == '12.3(11)T8') flag++;
else if (version == '12.3(11)T7') flag++;
else if (version == '12.3(11)T6') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
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
else if (version == '12.3(7)T9') flag++;
else if (version == '12.3(7)T8') flag++;
else if (version == '12.3(7)T7') flag++;
else if (version == '12.3(7)T6') flag++;
else if (version == '12.3(7)T4') flag++;
else if (version == '12.3(7)T3') flag++;
else if (version == '12.3(7)T2') flag++;
else if (version == '12.3(7)T12') flag++;
else if (version == '12.3(7)T11') flag++;
else if (version == '12.3(7)T10') flag++;
else if (version == '12.3(7)T1') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(4)T9') flag++;
else if (version == '12.3(4)T8') flag++;
else if (version == '12.3(4)T7') flag++;
else if (version == '12.3(4)T6') flag++;
else if (version == '12.3(4)T4') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T11') flag++;
else if (version == '12.3(4)T10') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.2(18)SXD6') flag++;
else if (version == '12.2(18)SXD5') flag++;
else if (version == '12.2(18)SXD4') flag++;
else if (version == '12.2(18)SXD3') flag++;
else if (version == '12.2(18)SXD2') flag++;
else if (version == '12.2(18)SXD1') flag++;
else if (version == '12.2(18)SXD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s500\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s4500\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s848\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s4848\s", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

