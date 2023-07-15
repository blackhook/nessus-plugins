#TRUSTED 4cc784772cdcbcae5c8c30fc96c45ebd8605f3f1232dfd97a7853c2339d9f096444a89722d544c76cfc51228b80fc13a0d5bec308ff7ec087c5c6db55d23349283a4a91326fe03b17b67c88647e6b4fdedcef02837b3d652b497efa92981681c9f34b864be1f311028ab7726d26d7b02424b27d8dd9da045242344191dc4890fd067f8dd11928a6c8d36ff3cab1a5b71858a56a93c030618c14a55c52c0b55c593673c39e53a5aa6eab765c75dfda61fab37ae893c6dc7abac090cb2214d6b7067e9b1b2ffe8f4ecd175ca0b5f663a76185771786a749a66602168b5b6409349868af3ce9a9a1759f1757106c53bb9044ab36f8d72303c1e8aee7157d0ddf7d170b7112621aa461b607c3b4ee1d2f28f23000819dcbe890ef483aacc63ea803b8bf52205f491936a00520f9d6d14746a2cfa313d11d11971436eba48a5de112b709f67c1475330a1f4cb8d2c2dbb455b96339c9266809df06ea2221d50282c695b7279c5113d715d565d87a8af646f70f179ff9ce358fda58aaf5033e4aeee517078291e64a425c5c76da041a8cb6d4e7c2a5b435b6b15dc45d35135d303a79773056cf5cee975480d5d499acc2e9e1e2c1b9f3e686cf11b3179fb3d72e6dcdff45be6bf044d8b1973b21f0cd7a805da4cfd38e8f5fd5680f1032c5b5dfd675c7d0c9e8ea30ce3c456e4e4190efa3dc929bea61973e13a9a91721259ef42d1c7
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-rsvp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(65890);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-1143");
  script_bugtraq_id(58743);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtg39957");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-rsvp");

  script_name(english:"Cisco IOS Software Resource Reservation Protocol Denial of Service Vulnerability (cisco-sa-20130327-rsvp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Resource Reservation Protocol (RSVP) feature in Cisco IOS Software
and Cisco IOS XE Software contains a vulnerability when used on a
device that has Multiprotocol Label Switching with Traffic Engineering
(MPLS-TE) enabled. Successful exploitation of the vulnerability could
allow an unauthenticated, remote attacker to cause a reload of the
affected device. Repeated exploitation could result in a sustained
denial of service (DoS) condition. Cisco has released free software
updates that address this vulnerability. There are no workarounds
available to mitigate this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-rsvp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83e71d5a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-rsvp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
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
if ( version == '12.2(33)SRE4' ) flag++;
if ( version == '12.2(33)SRE5' ) flag++;
if ( version == '12.2(33)SRE6' ) flag++;
if ( version == '12.2(33)SRE7' ) flag++;
if ( version == '12.2(33)SRE7a' ) flag++;
if ( version == '12.2(33)ZI' ) flag++;
if ( version == '12.2(58)EX' ) flag++;
if ( version == '12.2(58)EZ' ) flag++;
if ( version == '12.2(58)SE2' ) flag++;
if ( version == '15.0(1)MR' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;
if ( version == '15.0(1)S3a' ) flag++;
if ( version == '15.0(1)S4' ) flag++;
if ( version == '15.0(1)S4a' ) flag++;
if ( version == '15.0(1)S5' ) flag++;
if ( version == '15.0(1)S6' ) flag++;
if ( version == '15.0(2)MR' ) flag++;
if ( version == '15.1(1)MR' ) flag++;
if ( version == '15.1(1)MR1' ) flag++;
if ( version == '15.1(1)MR2' ) flag++;
if ( version == '15.1(1)MR3' ) flag++;
if ( version == '15.1(1)MR4' ) flag++;
if ( version == '15.1(1)MR5' ) flag++;
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)SA' ) flag++;
if ( version == '15.1(1)SA1' ) flag++;
if ( version == '15.1(1)SA2' ) flag++;
if ( version == '15.1(1)SY' ) flag++;
if ( version == '15.1(2)EY' ) flag++;
if ( version == '15.1(2)EY1' ) flag++;
if ( version == '15.1(2)EY1a' ) flag++;
if ( version == '15.1(2)EY2' ) flag++;
if ( version == '15.1(2)EY2a' ) flag++;
if ( version == '15.1(2)EY3' ) flag++;
if ( version == '15.1(2)EY4' ) flag++;
if ( version == '15.1(2)S' ) flag++;
if ( version == '15.1(2)S1' ) flag++;
if ( version == '15.1(2)S2' ) flag++;
if ( version == '15.1(2)SNG' ) flag++;
if ( version == '15.1(2)SNH' ) flag++;
if ( version == '15.1(2)SNH1' ) flag++;
if ( version == '15.1(2)SNI' ) flag++;
if ( version == '15.1(3)MR' ) flag++;
if ( version == '15.1(3)MRA' ) flag++;
if ( version == '15.1(3)S' ) flag++;
if ( version == '15.1(3)S0a' ) flag++;
if ( version == '15.1(3)S1' ) flag++;
if ( version == '15.1(3)S2' ) flag++;
if ( version == '15.1(3)S3' ) flag++;
if ( version == '15.1(3)S4' ) flag++;
if ( version == '15.2(1)S' ) flag++;
if ( version == '15.2(1)S1' ) flag++;
if ( version == '15.2(1)S2' ) flag++;
if ( version == '15.2(1)SA' ) flag++;
if ( version == '15.2(1)SB' ) flag++;
if ( version == '15.2(1)SB1' ) flag++;
if ( version == '15.2(1)SB2' ) flag++;
if ( version == '15.2(1)SB3' ) flag++;
if ( version == '15.2(1)SB4' ) flag++;
if ( version == '15.2(1)SC' ) flag++;
if ( version == '15.2(1)SC1' ) flag++;
if ( version == '15.2(2)S' ) flag++;
if ( version == '15.2(2)S0a' ) flag++;
if ( version == '15.2(2)S0b' ) flag++;
if ( version == '15.2(2)S0c' ) flag++;
if ( version == '15.2(2)S0d' ) flag++;
if ( version == '15.2(2)S1' ) flag++;
if ( version == '15.2(2)S2' ) flag++;
if ( version == '15.2(2)SNG' ) flag++;
if ( version == '15.2(2)SNH' ) flag++;
if ( version == '15.2(2)SNH1' ) flag++;
if ( version == '15.2(4)S' ) flag++;
if ( version == '15.2(4)S0c' ) flag++;
if ( version == '15.2(4)S0xb' ) flag++;
if ( version == '15.2(4)S1' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"mpls traffic-eng tunnels", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
