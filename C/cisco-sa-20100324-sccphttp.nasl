#TRUSTED 1d2934b5fa16247b3105480e32884e766ab57ae1468761f699a6a767834d49ed3bd4ae44c085e5be539030236dc68ddbe248296b02cfcb825205a45ae99879fa4c5041274d1e74685ff2849ab8cb8afc5e0873849f4dacffbabc3299ad840da6569bc38ba5e2b0bf3f7dad1a0d9908b36378e2a4a0d332ebedcc810352134b56d9785395cbc6d5b4014db8be6bfe78589fd3112aaa1ebedd0c090d05a02e28991f40681c94f9aa6d2f20695a756a995b787e1e27d3b87e1112146a062441e1b9e115d2fc6b452791e3c9356127159e575424d8f39b5591022e48e9f598fead463a64285d4fba14fa69bba08a4ddeb6cf10cb4b1d4fe80794f7f10597e94ba88858f7fb5bd3b191fd1d4e65f0e421252b33a3d481b16dd0e3ea025aab7436c340c7a434b80a5ed11c5c1783c71bfa43069ffb63ea88f0fb8baa3a1bfcb063938c2ae6ce5e16ef9f9409a2875f3a90c6cfcfae43cec936136a7cf64108d389c0bbe5c78eda59b7a4d0e2d261f05c910e2c638a6223891a1c84ddceb67ba410bf7e89fd1c236ac745e74f3daa850d6d89d23223d173fdf1897f4e03da3e7a0ca3e9592d06e37b92410e2ba788f9d1644b900fb83c7e37951fe3dd67cb92e5e2cdc39b983bc365515b63b8c863507434411f6ac38ef22c43f5c285639b1610c4fa08176b1c34007e893b96e84553fb703e924b7b2cabfc48b4303fe2f4bf323a0047
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100324-sccp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(49053);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2010-0584");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsy09250");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100324-sccp");

  script_name(english:"Cisco IOS Software NAT Skinny Call Control Protocol Vulnerability (cisco-sa-20100324-sccp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Skinny Client Control Protocol (SCCP) crafted messages may cause a
Cisco IOS device that is configured with the Network Address
Translation (NAT) SCCP Fragmentation Support feature to reload. Cisco
has released free software updates that address this vulnerability. A
workaround that mitigates this vulnerability is available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100324-sccp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fa15208"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100324-sccp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");
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
if ( version == '12.4(11)MD' ) flag++;
if ( version == '12.4(11)MD1' ) flag++;
if ( version == '12.4(11)MD2' ) flag++;
if ( version == '12.4(11)MD3' ) flag++;
if ( version == '12.4(11)MD4' ) flag++;
if ( version == '12.4(11)MD5' ) flag++;
if ( version == '12.4(11)MD6' ) flag++;
if ( version == '12.4(11)MD7' ) flag++;
if ( version == '12.4(11)MD8' ) flag++;
if ( version == '12.4(11)MD9' ) flag++;
if ( version == '12.4(11)MR' ) flag++;
if ( version == '12.4(11)SW' ) flag++;
if ( version == '12.4(11)SW1' ) flag++;
if ( version == '12.4(11)SW2' ) flag++;
if ( version == '12.4(11)SW3' ) flag++;
if ( version == '12.4(11)T' ) flag++;
if ( version == '12.4(11)T1' ) flag++;
if ( version == '12.4(11)T2' ) flag++;
if ( version == '12.4(11)T3' ) flag++;
if ( version == '12.4(11)T4' ) flag++;
if ( version == '12.4(11)XJ' ) flag++;
if ( version == '12.4(11)XJ1' ) flag++;
if ( version == '12.4(11)XJ2' ) flag++;
if ( version == '12.4(11)XJ3' ) flag++;
if ( version == '12.4(11)XJ4' ) flag++;
if ( version == '12.4(11)XJ5' ) flag++;
if ( version == '12.4(11)XJ6' ) flag++;
if ( version == '12.4(11)XV' ) flag++;
if ( version == '12.4(11)XV1' ) flag++;
if ( version == '12.4(11)XW' ) flag++;
if ( version == '12.4(11)XW1' ) flag++;
if ( version == '12.4(11)XW10' ) flag++;
if ( version == '12.4(11)XW2' ) flag++;
if ( version == '12.4(11)XW3' ) flag++;
if ( version == '12.4(11)XW4' ) flag++;
if ( version == '12.4(11)XW5' ) flag++;
if ( version == '12.4(11)XW6' ) flag++;
if ( version == '12.4(11)XW7' ) flag++;
if ( version == '12.4(11)XW8' ) flag++;
if ( version == '12.4(11)XW9' ) flag++;
if ( version == '12.4(12)MR' ) flag++;
if ( version == '12.4(12)MR1' ) flag++;
if ( version == '12.4(12)MR2' ) flag++;
if ( version == '12.4(14)XK' ) flag++;
if ( version == '12.4(15)MD' ) flag++;
if ( version == '12.4(15)MD1' ) flag++;
if ( version == '12.4(15)MD2' ) flag++;
if ( version == '12.4(15)MD3' ) flag++;
if ( version == '12.4(15)SW' ) flag++;
if ( version == '12.4(15)SW1' ) flag++;
if ( version == '12.4(15)SW2' ) flag++;
if ( version == '12.4(15)SW3' ) flag++;
if ( version == '12.4(15)SW4' ) flag++;
if ( version == '12.4(15)T' ) flag++;
if ( version == '12.4(15)T1' ) flag++;
if ( version == '12.4(15)T2' ) flag++;
if ( version == '12.4(15)T3' ) flag++;
if ( version == '12.4(15)T4' ) flag++;
if ( version == '12.4(15)T5' ) flag++;
if ( version == '12.4(15)T6' ) flag++;
if ( version == '12.4(15)T6a' ) flag++;
if ( version == '12.4(15)T7' ) flag++;
if ( version == '12.4(15)T8' ) flag++;
if ( version == '12.4(15)T9' ) flag++;
if ( version == '12.4(15)XF' ) flag++;
if ( version == '12.4(15)XL' ) flag++;
if ( version == '12.4(15)XL1' ) flag++;
if ( version == '12.4(15)XL2' ) flag++;
if ( version == '12.4(15)XL3' ) flag++;
if ( version == '12.4(15)XL4' ) flag++;
if ( version == '12.4(15)XL5' ) flag++;
if ( version == '12.4(15)XM' ) flag++;
if ( version == '12.4(15)XM1' ) flag++;
if ( version == '12.4(15)XM2' ) flag++;
if ( version == '12.4(15)XM3' ) flag++;
if ( version == '12.4(15)XN' ) flag++;
if ( version == '12.4(15)XQ' ) flag++;
if ( version == '12.4(15)XQ1' ) flag++;
if ( version == '12.4(15)XQ2' ) flag++;
if ( version == '12.4(15)XQ2a' ) flag++;
if ( version == '12.4(15)XQ2b' ) flag++;
if ( version == '12.4(15)XQ2c' ) flag++;
if ( version == '12.4(15)XQ3' ) flag++;
if ( version == '12.4(15)XQ4' ) flag++;
if ( version == '12.4(15)XR' ) flag++;
if ( version == '12.4(15)XR1' ) flag++;
if ( version == '12.4(15)XR2' ) flag++;
if ( version == '12.4(15)XR3' ) flag++;
if ( version == '12.4(15)XR4' ) flag++;
if ( version == '12.4(15)XR5' ) flag++;
if ( version == '12.4(15)XR6' ) flag++;
if ( version == '12.4(15)XR7' ) flag++;
if ( version == '12.4(15)XR8' ) flag++;
if ( version == '12.4(15)XY' ) flag++;
if ( version == '12.4(15)XY1' ) flag++;
if ( version == '12.4(15)XY2' ) flag++;
if ( version == '12.4(15)XY3' ) flag++;
if ( version == '12.4(15)XY4' ) flag++;
if ( version == '12.4(15)XY5' ) flag++;
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(16)MR' ) flag++;
if ( version == '12.4(16)MR1' ) flag++;
if ( version == '12.4(16)MR2' ) flag++;
if ( version == '12.4(19)MR' ) flag++;
if ( version == '12.4(19)MR1' ) flag++;
if ( version == '12.4(19)MR2' ) flag++;
if ( version == '12.4(20)MR' ) flag++;
if ( version == '12.4(20)MR2' ) flag++;
if ( version == '12.4(20)T' ) flag++;
if ( version == '12.4(20)T1' ) flag++;
if ( version == '12.4(20)T2' ) flag++;
if ( version == '12.4(20)T3' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)MD' ) flag++;
if ( version == '12.4(22)MD1' ) flag++;
if ( version == '12.4(22)MDA' ) flag++;
if ( version == '12.4(22)MDA1' ) flag++;
if ( version == '12.4(22)MF' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)XR' ) flag++;
if ( version == '12.4(22)XR1' ) flag++;
if ( version == '12.4(22)XR2' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YD' ) flag++;
if ( version == '12.4(22)YD1' ) flag++;
if ( version == '12.4(22)YD2' ) flag++;
if ( version == '12.4(22)YE' ) flag++;
if ( version == '12.4(22)YE1' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)YG1' ) flag++;
if ( version == '12.4(4)XC' ) flag++;
if ( version == '12.4(4)XC1' ) flag++;
if ( version == '12.4(4)XC2' ) flag++;
if ( version == '12.4(4)XC3' ) flag++;
if ( version == '12.4(4)XC4' ) flag++;
if ( version == '12.4(4)XC5' ) flag++;
if ( version == '12.4(4)XC6' ) flag++;
if ( version == '12.4(4)XC7' ) flag++;
if ( version == '12.4(6)MR' ) flag++;
if ( version == '12.4(6)MR1' ) flag++;
if ( version == '12.4(6)T' ) flag++;
if ( version == '12.4(6)T1' ) flag++;
if ( version == '12.4(6)T10' ) flag++;
if ( version == '12.4(6)T11' ) flag++;
if ( version == '12.4(6)T12' ) flag++;
if ( version == '12.4(6)T2' ) flag++;
if ( version == '12.4(6)T3' ) flag++;
if ( version == '12.4(6)T4' ) flag++;
if ( version == '12.4(6)T5' ) flag++;
if ( version == '12.4(6)T5a' ) flag++;
if ( version == '12.4(6)T5b' ) flag++;
if ( version == '12.4(6)T5c' ) flag++;
if ( version == '12.4(6)T5d' ) flag++;
if ( version == '12.4(6)T5e' ) flag++;
if ( version == '12.4(6)T5f' ) flag++;
if ( version == '12.4(6)T6' ) flag++;
if ( version == '12.4(6)T7' ) flag++;
if ( version == '12.4(6)T8' ) flag++;
if ( version == '12.4(6)T9' ) flag++;
if ( version == '12.4(6)XE' ) flag++;
if ( version == '12.4(6)XE1' ) flag++;
if ( version == '12.4(6)XE2' ) flag++;
if ( version == '12.4(6)XE3' ) flag++;
if ( version == '12.4(6)XE4' ) flag++;
if ( version == '12.4(6)XP' ) flag++;
if ( version == '12.4(6)XT' ) flag++;
if ( version == '12.4(6)XT1' ) flag++;
if ( version == '12.4(6)XT2' ) flag++;
if ( version == '12.4(9)MR' ) flag++;
if ( version == '12.4(9)T' ) flag++;
if ( version == '12.4(9)T0a' ) flag++;
if ( version == '12.4(9)T1' ) flag++;
if ( version == '12.4(9)T2' ) flag++;
if ( version == '12.4(9)T3' ) flag++;
if ( version == '12.4(9)T4' ) flag++;
if ( version == '12.4(9)T5' ) flag++;
if ( version == '12.4(9)T6' ) flag++;
if ( version == '12.4(9)T7' ) flag++;
if ( version == '12.4(9)XG' ) flag++;
if ( version == '12.4(9)XG1' ) flag++;
if ( version == '12.4(9)XG2' ) flag++;
if ( version == '12.4(9)XG3' ) flag++;
if ( version == '12.4(9)XG4' ) flag++;
if ( version == '12.4(9)XG5' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"\n\s*ip nat inside\n", multiline:TRUE, string:buf)) && (preg(pattern:"\n\s*ip nat outside\n", multiline:TRUE, string:buf)) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_nat_nvi_statistics", "show ip nat nvi statistics");
    if (check_cisco_result(buf)) { flag = 1; }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
