#TRUSTED 84c73f4db6f7aec3d2e7926d9a931d623c2b9fc7ee7487f23192c0ca9e1f096404e1c6d4230689c565dc7fbd65bcaa6c5e852d8b252c295a4d6dc7bf1f04049fea0e864f8cd3512546ac09c0437057b2ec495970f6650b360ccc5764a7061e3b8061c3fdf656bb7ed9487c093b662fe5d8f3601ec9d83c20843766dcd34ec5bca6ce928940db93fe4f955db461d0c775be04ca656104027d30f5f99ecf67f10a72f77da23422450397978949044e957e4d281543146366b8931ad93d6dddfadd92d6c57104ca18a54159e03db25750c76f6d5fce346ce377cf895743f7163ec164d5e2108103b6747d434d7acf2d49c34a9b2d5cb2c7156817f2e9f52ce5c2528efaefd14ea921e80f8bc9a16791a11991a617602f91202d85061fe18fd1d8c088402b774afc138d36af58260bf84753003fa7ee3ad504e07546a01e1813ac17adf82119ce31a59f84ad952567f98f3d31028037387b4c0d3be8f4db3662bf02c0c018ff28f24dfa26034b3e7486d1e0778fb4afc05bf6cc4a1a7dfe30cb669208ba748f114dd55e4c287e9f2739676fce95d2088e6cfcf3c970293bab045bbf685954f659a1b02f206cb57fa4c5442b78551d0f6bf32bce40737f8615d9f6aed1ab4b0dfda99be6d0bdb92e83447b6ca86dc00382ae4ea6284e8ac3f200ae36f51c88261747895fe29cd718dd509dd1c67bdfe7932dff107354860d34be9b3c
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-ipv6.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56316);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2011-0944");
  script_bugtraq_id(49821);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtj41194");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-ipv6");

  script_name(english:"Cisco IOS Software IPv6 Denial of Service Vulnerability (cisco-sa-20110928-ipv6)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability in the IP version 6 (IPv6)
protocol stack implementation that could allow an unauthenticated,
remote attacker to cause a reload of an affected device that has IPv6
operation enabled. The vulnerability is triggered when an affected
device processes a malformed IPv6 packet. Cisco has released free
software updates that address this vulnerability. There are no
workarounds to mitigate this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-ipv6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99a00689"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-ipv6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.2(33)SRE' ) flag++;
if ( version == '12.2(33)SRE0a' ) flag++;
if ( version == '12.2(33)SRE1' ) flag++;
if ( version == '12.2(33)SRE2' ) flag++;
if ( version == '12.2(33)SRE3' ) flag++;
if ( version == '12.2(33)XNE' ) flag++;
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(33)XNE1xb' ) flag++;
if ( version == '12.2(33)XNE2' ) flag++;
if ( version == '12.2(33)XNE3' ) flag++;
if ( version == '12.2(33)XNF' ) flag++;
if ( version == '12.2(33)XNF1' ) flag++;
if ( version == '12.2(33)XNF2' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)GC3' ) flag++;
if ( version == '12.4(24)GC3a' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(24)T4' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)MR' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;
if ( version == '15.0(1)S3a' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.0(2)MR' ) flag++;
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)SA1' ) flag++;
if ( version == '15.1(1)SA2' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)S' ) flag++;
if ( version == '15.1(2)S1' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ipv6\s+address", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ipv6\s+enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
