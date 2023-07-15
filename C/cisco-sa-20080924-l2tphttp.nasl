#TRUSTED 2c4e11c10038e1c14b7dafd9ecebfa62ca554a3facc1cb4f384559acce03c82107e679fda11f1640086569c73f2d4f3480b946eff3a2f54344ad4d2c363508b261c7cc35137cba8778f9bf41883a0b549f0e5f09717d2b8b7268cdb800a1fad360856a72a8a17444b4cc407ad9157090acb44a6effd0b63da10da6f760e3fede920d37f1d79e7f6c13b0c43fbcdde5b45460f24dc29beca6b6a1126d610113929f50f617525d0e7c921483780bf33cedda5de780337a613c707d77ecb452a0d2568bd391f9462e4f8de63f81fee1ff07fcf074ce2cedd0068a9f81e8e91e27e98afbd4cb6f0c7c4b72d957763d4d1bd4256299526ec4c34a78112506b1584ca31ee595dd086b1ed364a791abf549bd5bd5a94d10088c6a1f0f78feb88103c34b3a9a9877b80cf0185cb3b42bbd927b15e79627051ebc43748882c6f9f09b33a7420da6d50368542532b92e447f913fac66abb219ebb2e8e8d459785bb0882b91247b81c8025cf0d386dba09d6ef1369b72cb9d4248cd6194499e33aa23d5343b4c131110c3e48eb7dda711eb90a1ccc13f27d344796e3fcbfc8a529ddde3451f34307f716341f63bbc1e7dca81d104f172662cbd40395ff9653dcfeaec19f9ccba0f60493cbc91a66d8c157d9e8fbbf449988a514ce7cf6945e3045c9cc7e2141ed1675e167a11720d3068fcab1f879ba1de957632d44749c68c116ff0d8dd13
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a0157a.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49021);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2008-3813");
 script_bugtraq_id(31358);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsh48879");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-l2tp");
script_name(english:"Cisco IOS Software Layer 2 Tunneling Protocol (L2TP) Denial of Service Vulnerability");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A vulnerability exists in the Cisco IOS software implementation of
Layer 2 Tunneling Protocol (L2TP), which affects limited Cisco IOS
software releases.
Several features enable the L2TP mgmt daemon process within Cisco IOS
software, including but not limited to Layer 2 virtual private networks
(L2VPN), Layer 2 Tunnel Protocol Version 3 (L2TPv3), Stack Group
Bidding Protocol (SGBP) and Cisco Virtual Private Dial-Up Networks
(VPDN). Once this process is enabled the device is vulnerable.
This vulnerability will result in a reload of the device when
processing a specially crafted L2TP packet.
Cisco has released free software updates that address this
vulnerability.
Workarounds that mitigate this vulnerability are available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e91861de");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a0157a.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?e477dd69");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-l2tp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
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

if (version == '12.4(11)XW') flag++;
else if (version == '12.4(11)XV1') flag++;
else if (version == '12.4(11)XV') flag++;
else if (version == '12.4(11)XJ4') flag++;
else if (version == '12.4(11)XJ3') flag++;
else if (version == '12.4(11)XJ2') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(11)T4') flag++;
else if (version == '12.4(11)T3') flag++;
else if (version == '12.4(11)T2') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(11)SW2') flag++;
else if (version == '12.4(11)SW1') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(12)MR2') flag++;
else if (version == '12.4(12)MR1') flag++;
else if (version == '12.4(12)MR') flag++;
else if (version == '12.4(11)MR') flag++;
else if (version == '12.2(33)SRB') flag++;
else if (version == '12.2(37)SG1') flag++;
else if (version == '12.2(40)SE') flag++;
else if (version == '12.2(37)SE1') flag++;
else if (version == '12.2(37)SE') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\sL2TP\s", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
