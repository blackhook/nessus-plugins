#TRUSTED 58f1186265eb8a7b58d866214217591e72fc38470a23e456529a22837f9c12d2250a902babb32cf5cad43733324c354052b1f3b46e16bbfb0a4e14a22353cfdf17afa7b59cbfd9a4cf9bb5dcfb82e35570d8908ae62f9f7c3ff41f7cd80c3a346a9be1b986d22ba41c1c9ead7e02fc98da5f03c050b02c0d756307d82dce6b6e837bee859116f10f3cfe64545c7f83af4565ad7113cd09026c4b2978d8af10eb4035e2da2e0fb765634d7cd40912b24ffb96086637ac275915700c2b4e52e4b33d5c95161e5a08bf53914366c50a09ada9a138125a00805ad494ef5ba77cfdbcfb72c100cefed028c6fffed3c66592d97198c8366ccac9eae5e2c51cd3e15d7eacccc1ea9ac34b1a70019582b25c7ae76e82086b2267a6143e2d7705c351160a7c7df3072bf41485c33435c0404079dafd2369dc1a29574c5400a456d17982d6de4ba16f1c09a1cd43b6a9daa178c10a3515b16e46961501432ea236932a7c1dbf058ee514542301d2cfcf22ca178c5d100d9957b358861a41a8795159be6d6b7a4e2c6b978b97baff209785236bd7eaeb8ac72efeefc4820c9c091dc0fcec43cdf21db992299597fe014c8afa08277b232109d997f61ce8ce0ab310bce36b11909ac1191b468fd3d413293b8bde7864593e74d41c4199024167bd456d7d6c86191854e9409b647f28852fa729063b3f8187ea485133081ad609cc6af0b77ecf
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-rsvp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70313);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5478");
  script_bugtraq_id(62646);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf17023");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-rsvp");

  script_name(english:"Cisco IOS Software Resource Reservation Protocol Interface Queue Wedge Vulnerability (cisco-sa-20130925-rsvp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote device is affected by a denial of service vulnerability due
to improper handling of UDP RSVP packets in the Resource Reservation
Protocol (RSVP) feature. An unauthenticated, remote attacker, via
specially-crafted UDP RSVP packets sent to port 1698, can trigger an
interface queue wedge, resulting in a loss of connectivity, loss of
routing protocol adjacency, and other denial of service conditions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-rsvp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe2616f7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-rsvp. Alternatively, apply the workaround referenced
in the advisory.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");
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

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M10' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)M8' ) flag++;
if ( version == '15.0(1)M9' ) flag++;
if ( version == '15.0(1)SY' ) flag++;
if ( version == '15.0(1)SY1' ) flag++;
if ( version == '15.0(1)SY2' ) flag++;
if ( version == '15.0(1)SY3' ) flag++;
if ( version == '15.0(1)SY4' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.1(1)MR' ) flag++;
if ( version == '15.1(1)MR1' ) flag++;
if ( version == '15.1(1)MR2' ) flag++;
if ( version == '15.1(1)MR3' ) flag++;
if ( version == '15.1(1)MR4' ) flag++;
if ( version == '15.1(1)MR5' ) flag++;
if ( version == '15.1(1)MR6' ) flag++;
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)SA' ) flag++;
if ( version == '15.1(1)SA1' ) flag++;
if ( version == '15.1(1)SA2' ) flag++;
if ( version == '15.1(1)SY' ) flag++;
if ( version == '15.1(1)SY1' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)T4' ) flag++;
if ( version == '15.1(1)T5' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(2)EY' ) flag++;
if ( version == '15.1(2)EY1' ) flag++;
if ( version == '15.1(2)EY1a' ) flag++;
if ( version == '15.1(2)EY2' ) flag++;
if ( version == '15.1(2)EY2a' ) flag++;
if ( version == '15.1(2)EY3' ) flag++;
if ( version == '15.1(2)EY4' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)GC2' ) flag++;
if ( version == '15.1(2)S' ) flag++;
if ( version == '15.1(2)S1' ) flag++;
if ( version == '15.1(2)S2' ) flag++;
if ( version == '15.1(2)SNG' ) flag++;
if ( version == '15.1(2)SNH' ) flag++;
if ( version == '15.1(2)SNH1' ) flag++;
if ( version == '15.1(2)SNI' ) flag++;
if ( version == '15.1(2)SNI1' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(2)T5' ) flag++;
if ( version == '15.1(3)MR' ) flag++;
if ( version == '15.1(3)MRA' ) flag++;
if ( version == '15.1(3)MRA1' ) flag++;
if ( version == '15.1(3)S' ) flag++;
if ( version == '15.1(3)S0a' ) flag++;
if ( version == '15.1(3)S1' ) flag++;
if ( version == '15.1(3)S2' ) flag++;
if ( version == '15.1(3)S3' ) flag++;
if ( version == '15.1(3)S4' ) flag++;
if ( version == '15.1(3)S5' ) flag++;
if ( version == '15.1(3)S5a' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(3)T3' ) flag++;
if ( version == '15.1(3)T4' ) flag++;
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)GC1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)M6' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)S' ) flag++;
if ( version == '15.2(1)S1' ) flag++;
if ( version == '15.2(1)S2' ) flag++;
if ( version == '15.2(1)SA' ) flag++;
if ( version == '15.2(1)SB' ) flag++;
if ( version == '15.2(1)SB1' ) flag++;
if ( version == '15.2(1)SB3' ) flag++;
if ( version == '15.2(1)SB4' ) flag++;
if ( version == '15.2(1)SC1a' ) flag++;
if ( version == '15.2(1)SC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(1)T3' ) flag++;
if ( version == '15.2(1)T3a' ) flag++;
if ( version == '15.2(1)T4' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)S' ) flag++;
if ( version == '15.2(2)S0a' ) flag++;
if ( version == '15.2(2)S0c' ) flag++;
if ( version == '15.2(2)S0d' ) flag++;
if ( version == '15.2(2)S1' ) flag++;
if ( version == '15.2(2)S2' ) flag++;
if ( version == '15.2(2)SNG' ) flag++;
if ( version == '15.2(2)SNH' ) flag++;
if ( version == '15.2(2)SNH1' ) flag++;
if ( version == '15.2(2)SNI' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(2)T2' ) flag++;
if ( version == '15.2(2)T3' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GC1' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)T3' ) flag++;
if ( version == '15.2(3)XA' ) flag++;
if ( version == '15.2(4)M' ) flag++;
if ( version == '15.2(4)M1' ) flag++;
if ( version == '15.2(4)M2' ) flag++;
if ( version == '15.2(4)M3' ) flag++;
if ( version == '15.2(4)S' ) flag++;
if ( version == '15.2(4)S0c' ) flag++;
if ( version == '15.2(4)S1' ) flag++;
if ( version == '15.2(4)S2' ) flag++;
if ( version == '15.2(4)S3' ) flag++;
if ( version == '15.2(4)S3a' ) flag++;
if ( version == '15.2(4)XB10' ) flag++;
if ( version == '15.3(1)S' ) flag++;
if ( version == '15.3(1)S1' ) flag++;
if ( version == '15.3(1)S1e' ) flag++;
if ( version == '15.3(1)S2' ) flag++;
if ( version == '15.3(1)T' ) flag++;
if ( version == '15.3(1)T1' ) flag++;
if ( version == '15.3(2)T' ) flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_rsvp", "show ip rsvp");
  if (check_cisco_result(buf))
  {
    if ("RSVP: enabled" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug IDs     : CSCuf17023' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
