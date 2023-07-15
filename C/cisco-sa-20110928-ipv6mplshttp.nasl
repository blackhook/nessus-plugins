#TRUSTED 15531bfa5628fce98261ef85835a1f2dd9ae0d95f05ba68d4b0516a3a035584725c661a09d1634146f9458339e1bcce55b248eabcfc29b04c8b66b9551df57f8a818eb3d40bc311fdc3d276c7a93877334b4d139542a73c4868f3daf2d6c01efa801709a7e38bb72afd3a6bbcad64b602abb4d0c7a4ebbc729b77770f49c7e1a8d8600dbc4fc91e431ab22811314cc2445bd0c81dc4a22b5e6e1c8309765bbee0829971124c0768b1dd8b88180fcf9bb6eb0212f45e01ecdde4e1380800b9ac128c1418ba508bb74f6964bca01097cb77c0edf2f7b7daa7bb23278bdd78fe9dd419c774fb3c3cfc20851285237bcf37f0bf59b79a794f83878c5efe5e96afd4c155ee262032768a5387de051cd4822319c6741db8c0808b58fdd5380c3116f3f4cb00356d0f7634c1b7e7041d6964058618eb7d47e2ff60f37deb7f6def263f864f07a2a7a3aa1cd4df01ed1b10af5240fc72a76212ffa4583b2e4b22b3e287b35571a8f95a9b1224464ee5f190c301382a93cd57981ae249a32ab6924edcf7dd3b0050b276e3ef9b991439dcb055c97e69775cf7518dd39c4bd2adc844a721cdd6bc24aba6097447fbc1a5952534e53774b55c5c63d392085a202217829abfd0160f2f0f0aa89182fb12aa3633e561e6634ab62841c476dbbbad1d7a952941b5c79d243debeabd53eeba8b8b7198bc03eabe39dc144f63fe93b9a80af301ca8
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-ipv6mpls.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56317);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2011-3274", "CVE-2011-3282");
  script_bugtraq_id(49827);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtj30155");
  script_xref(name:"CISCO-BUG-ID", value:"CSCto07919");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-ipv6mpls");

  script_name(english:"Cisco IOS Software IP Version 6 over Multiprotocol Label Switching Vulnerabilities (cisco-sa-20110928-ipv6mpls)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software is affected by two vulnerabilities that cause a
Cisco IOS device to reload when processing IP version 6 (IPv6) packets
over a Multiprotocol Label Switching (MPLS) domain. These
vulnerabilities are :

   - Crafted IPv6 Packet May Cause MPLS-Configured Device to
    Reload

   - ICMPv6 Packet May Cause MPLS-Configured Device to
    Reload

Cisco has released free software updates that address these
vulnerabilities.

Workarounds that mitigate these vulnerabilities are available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-ipv6mpls
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd0b6233"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-ipv6mpls."
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
    buf = cisco_command_kb_item("Host/Cisco/Config/show_mpls_interface", "show mpls interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Yes", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
