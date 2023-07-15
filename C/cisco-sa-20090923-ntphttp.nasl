#TRUSTED 8aca7609d80330e6a12131c23877b87207fc97a72d2c002a6891bdf9b4bee0bdc8ac77e2bdd939d2a3fcf29b79dcde4de65b59830f8c20e8d42b799e282391dd6d67bed9c247675b9ca4db7863ea12dfcf64a3b2ae57611bd7c9a8c924ea462649534dcd4f9e3e61ff0f60116191b3e0ac0e6238996395dfa64c066a5a5ec252e6409bde1181cade93bb803b6b90518a307717a0a46cc4305c1e34235383c1f6a7ce9782249ab3076045eefc4ab2d8854fdcb4c75e7b9e13a0e3486205e10b76529e1b26a099b9fa262582906054682f645937c6ef63c50386c86303d27d6202a6bede2db63a5707475694ca6e8d2f054a1134464534c326efd0844ede3edc248e3a8a1d6218f05b2e5350cc6d471b6c2d9e8da4cd5c32d709f55beb2caf16d835c86ec85a03510c3807be8d38a813f9261d9868e8fab8e1f6ab72d889a87ea005553b466b2facd80956df5f583adec1b1a24f6aac003c2a515f5fc14ed170f21f87b44f277ba43b7254e8745b6f15874dde2ffa656afdab0aab490ea835331e53f284aafdb92da8a2fa1db885e1697476d608440f2c219a028e672ef3a34d334daf279c0d0502e7389e356960ed812da79435805665494e3c804dca0833a8e316b239c74d5ac5b1046beb689179a7e57bf4aee83d3671329c504dc458a6f632c8b892131791f307fb190638c1eaaa9bd39298398a293536d3f6c8bcd96c47ca
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8131.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49045);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2009-2869");
 script_bugtraq_id(36502);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsu24505");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv75948");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsw79186");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-ntp");
 script_name(english:"Cisco IOS Software Network Time Protocol Packet Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco IOS Software with support for Network Time Protocol (NTP)
version (v4) contains a vulnerability processing specific NTP packets
that will result in a reload of the device. This results in a remote
denial of service (DoS) condition on the affected device.
Cisco has released free software updates that address this
vulnerability.
Workarounds that mitigate this vulnerability are available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29ebdce8");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8131.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?e726ce77");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-ntp.");
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

if (version == '12.4(22)YE') flag++;
else if (version == '12.4(22)YD') flag++;
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
else if (version == '12.4(22)MD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ntp master", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ntp peer", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ntp server", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ntp broadcast client", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ntp multicast client", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
