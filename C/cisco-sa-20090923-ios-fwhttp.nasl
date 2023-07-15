#TRUSTED 52bfda0214b09f0f3e3ac6371e12346ba55f8db438c318ce93796a28faa6baa16e41cd0b532aa10e739d6f977c96fb734a391a432ee766b491ee299073254e39a76a83fe9e882a021f54660947c293b85bf47e3831fbb69925611b37edb354e9650cba421043eb127d762355d66d08ca2da6926963beb5794a0542d8d8c0dc8c70c4f26772927016d998d9b5995ecf60fa240cf28916a7d1134d921f227eda9e3a400a20204b543fd2fb0545a93909fdeab71b54c00cb9b522d990f0c288316f330f00b15907c87b01060d4ec5dd8b54c1d75c3dcf1c442d267e61a7d3c24cdae35fc94e89c8a10d43b08ac182662ee3e7adb4e5a117df7636c214d57054f4e3df3607ea0d4ed20dd31094edc67ec2de7ec0c71ec23dfc5838193afb7ec616ce25cc907ce849db50027167a5ed84e6924aef0edf7c3654d1e3e9c71755399a40f18b7e5d37dcf6de7c0e0c8cef592bc42c5e47b029981324fef434a61f6537cd08d75795f625b3f3576588a7a2c0b4db7b77e59a969796ea018cc60bd1964909d2179302b37c3b2b41848b8863d7c4dd683326a9006b1f9bc0fe7b68b80c93c4c4945eeaaaea9fcd3c97bc5fc71d9f86608d2800d591d86f814dbf1f4e1dc15370ee70961478d80fd2fb6f279c7697ef5d5983fbc796a60ebbe50349992b852622a31119d2ef211cd3ffcf84a8ddd7f7c3fadd383b63fe90253a9d5a28a12dd8
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8130.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49043);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2009-2867");
 script_bugtraq_id(36492);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsr18691");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-ios-fw");
 script_name(english:"Cisco IOS Software Zone-Based Policy Firewall Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco IOS devices that are configured with Cisco IOS Zone-Based
Policy Firewall Session Initiation Protocol (SIP) inspection are
vulnerable to denial of service (DoS) attacks when processing a
specific SIP transit packet. Exploitation of the vulnerability could
result in a reload of the affected device.
Cisco has released free software updates that address this
vulnerability.
Workarounds that mitigate this vulnerability are available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dac9c078");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8130.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?38b4dfb7");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-ios-fw.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
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

if (version == '12.4(22)YB1') flag++;
else if (version == '12.4(22)YB') flag++;
else if (version == '12.4(20)YA3') flag++;
else if (version == '12.4(20)YA2') flag++;
else if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ2') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(22)T') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair", "show policy-map type inspect zone-pair");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Match: ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
