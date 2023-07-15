#TRUSTED 2e9f711f64228ba663a24ef04bad5703cbb6806beef147cbbb6c67b783c88936defa1cf5f5c4455a9db4126ec0929598042bcb0098ac4f476409a11051db26c82644c262a3ce6489e94169380d254af1b757b5effd62acc327659e004395d23cd7d293c5ffe6e093e2fcd0fbc5b257f9c1dc6585463f7d2cea3747b723499f8bd7e23cb7188ef5f78792951cc2c4efdfaf3cd723660c889e28c252611086dc3df153dfbe5d39380cc7a2d9f9c02fb9b91e6c1f92b74a855dd0a558489b93796be9b8909e6247e8553b59893f59e8a379db13f14a9c4b3942e903bd34a29baf90788360d0206b1ab15a8b11a218772b415c2b560645e33c5cc08260523873208b212f9e86f27be97776a1b0ff28cfcf75e7567abe8f3c97ccd72548643307e35ddb7a25b209d815e716ff9e394b92b93b14065b78c98c3dadaed3cc73238264b0e2c6dfbd699ad46ae1f3a82025c45a8ef85b648543fa5528c0ebbd78d4d59b7f64dbfc513da01ad6404e836bbf0451071c1027f3a6a344d74a5933cefae733ed904117c11baac9839dc58a4ef76deb2611db28b609c31fd80c92a163065576e2fb464771172cc2013ee1bb85d289e66731de9f2edb1418b9a0d8b9d380c5d053507b1bd658530c3777c2a9c939d8b1d3849775402fe6f22ea4ef45f7793e943af5fec5111f6421f02a10f77a1d1790b1fe75eafdff556dd635161fdb9d845a1c
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a96c25.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49031);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2009-0633", "CVE-2009-0634");
 script_bugtraq_id(34241);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsm97220");
 script_xref(name:"CISCO-BUG-ID", value:"CSCso05337");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090325-mobileip");
 script_name(english:"Cisco IOS Software Mobile IP and Mobile IPv6 Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Devices that are running Cisco IOS Software and configured for Mobile
IP Network Address Translation (NAT) Traversal feature or Mobile IPv6
are vulnerable to a denial of service (DoS) attack that may result in a
blocked interface.

 Cisco has released free software updates that address these
vulnerabilities.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?391a7dca");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a96c25.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?a2c1d941");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090325-mobileip.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/03/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

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

if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(11)XW9') flag++;
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
else if (version == '12.4(15)XR3') flag++;
else if (version == '12.4(15)XR2') flag++;
else if (version == '12.4(15)XR1') flag++;
else if (version == '12.4(15)XR') flag++;
else if (version == '12.4(15)XQ1') flag++;
else if (version == '12.4(15)XQ') flag++;
else if (version == '12.4(6)XP') flag++;
else if (version == '12.4(15)XN') flag++;
else if (version == '12.4(15)XM2') flag++;
else if (version == '12.4(15)XM1') flag++;
else if (version == '12.4(15)XM') flag++;
else if (version == '12.4(15)XL3') flag++;
else if (version == '12.4(15)XL2') flag++;
else if (version == '12.4(15)XL1') flag++;
else if (version == '12.4(15)XL') flag++;
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
else if (version == '12.4(4)XD11') flag++;
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
else if (version == '12.4(2)XB9') flag++;
else if (version == '12.4(2)XB8') flag++;
else if (version == '12.4(2)XB7') flag++;
else if (version == '12.4(2)XB6') flag++;
else if (version == '12.4(2)XB5') flag++;
else if (version == '12.4(2)XB4') flag++;
else if (version == '12.4(2)XB3') flag++;
else if (version == '12.4(2)XB2') flag++;
else if (version == '12.4(2)XB10') flag++;
else if (version == '12.4(2)XB1') flag++;
else if (version == '12.4(2)XB') flag++;
else if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(15)T7') flag++;
else if (version == '12.4(15)T6') flag++;
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
else if (version == '12.4(23)') flag++;
else if (version == '12.4(21a)') flag++;
else if (version == '12.4(21)') flag++;
else if (version == '12.4(19b)') flag++;
else if (version == '12.4(19a)') flag++;
else if (version == '12.4(19)') flag++;
else if (version == '12.4(18c)') flag++;
else if (version == '12.4(18b)') flag++;
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
else if (version == '12.3(14)YX9') flag++;
else if (version == '12.3(14)YX4') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS2') flag++;
else if (version == '12.3(14)YQ8') flag++;
else if (version == '12.3(14)YQ7') flag++;
else if (version == '12.3(14)YQ6') flag++;
else if (version == '12.3(14)YQ5') flag++;
else if (version == '12.3(14)YQ4') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
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
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(14)T7') flag++;
else if (version == '12.3(14)T6') flag++;
else if (version == '12.3(14)T5') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip mobile home-agent nat traversal", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip mobile foreign-agent nat traversal", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip mobile router-service collocated registration nat traversal", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ipv6 mobile home-agent nat traversal", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ipv6 mobile foreign-agent nat traversal", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ipv6 mobile router-service collocated registration nat traversal", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
