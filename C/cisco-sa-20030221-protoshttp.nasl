#TRUSTED b2ebb32c64045d39a801389da0ea0e778f1280766700f212308675b5a84a645d53a83eb12b52900a088c70afe3b31c5b3a30d1eeb34891ade2f7d1cae35406b2deb9e64f1f0955dde6296ea27d83f1b6068f9ebd65c5a434ab8242d164f58e184c3be7dfbc32a3aeb93c69310683043ddf3389d00999e735918e922649e14d4466e7cd7d8e7b43f6f285b9a2f00963e26932401de094e3247377b97bb814923ce64abf97427e83444462625b64bac11b04fd4bdbf4bea30d3e1d18143f7cedd9aaa82f79b8dd37edbcda87db63ab4d251aeb14bdb9ec981e4f7859741da236bfdf845e0eb656f599691f54cddb7e8fe474014a8c724ebc667c38c8b23e09cd3204822ecff3e394ea5e6704b5b4f72032294dd6cb6f4359a6a2f9d9e02fbe7507a1aa9d9157af932e4a8e2123831ca2a4c06078b2fe60be7f3d6fe884bf8320725a937e30422120e71015a643bdb6f779e92dc40cdf9402a2a2949fc83ed83da4592d6828f609ef1dd445215c7ac6588258e34ab63d34bd2d6e4bab6ccbf28db7996535fdc388995927138f5a9fabd5a0dcd03a6196688426de1b8ac3984ee2e8f26203b61d80e41d598f776ef200610ab335f08d315e3dba3cdbbe506da67a2afac93d48fb7867cebdeb9f8fa17072f63217279a5a553f6734fdd60a87c44133da96ca4f3aaa7c09465cc9d00ea1bab8295520e1077f7876724795965f16607a
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a008014a251.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48969);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2003-1109");
 script_bugtraq_id(6904);
 script_xref(name:"CERT-CC", value:"528719");
 script_xref(name:"CERT-CC", value:"CA-2003-06");
 script_name(english:"Multiple Product Vulnerabilities Found by PROTOS SIP Test Suite - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
' Multiple Cisco products contain vulnerabilities in the processing of
Session Initiation Protocol (SIP) INVITE messages. These
vulnerabilities were identified by the University of Oulu Secure
Programming Group (OUSPG) "PROTOS" Test Suite for SIP and can be
repeatedly exploited to produce a denial of service.
');
 script_set_attribute(attribute:"see_also", value:"https://www.ee.oulu.fi/research/ouspg/PROTOS_Test-Suite_c07-sip");
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20030221-protos
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?5753c28d");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a008014a251.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?f555e750");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20030221-protos.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/21");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/02/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx47789");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz26317");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz29003");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz29033");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz29041");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz39284");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdz41124");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20030221-protos");
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
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

# Affected: 12.2 T
if (check_release(version: version,
                  patched: make_list("12.2(11)T3", "12.2(13)T1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SIP", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

