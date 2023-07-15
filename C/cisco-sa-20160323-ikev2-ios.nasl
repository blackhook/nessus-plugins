#TRUSTED 77bbb839d5399feec0ef1cee667a671dca33d1f6e07429d934a4f6ba43a258bcd06a69bfe24d763d620b46e78b2a0429296a7d1b392eb1aa7550e3fcebabdf2b6ff9f6080865de06f1577676d85609179b812373d0304ff36c41d2700f76fdf38883facfe5ec5f5c2468ee358d4991302af9cf3928b75831c85c0ddbd657a66b4099d746dbd5792e7dc33c0110700b6ff06517dfc2dd84cbc03ea3bd476f88cf0d902408281960552978450103b00d71c1231c9556402332b696764c3a9d4df0c1c9309defffc3695e53d03f4c7c17eb919206d90894ea8bbe24a7f24a4d1457dab95e7212484e1dca07c3bd9277998d826745fcc7cc28f581829bc6d7d7c78b4c78ac08958a6eb145c1916e0595aa96b96f979ff5f6771a9869d80590a62777d81d933852e435707a5f75aed87f277476c9f065ec3f0cc7fa9246a9c6e29c134af626980589c60e41933d90b77cdc92f6af37176ee49e985642a0762c9156a4ee11bbbe6ba7e99bf8435811778730cf1b13c0ad6d43bdd15b0c3c9f8570ea28c6a3822c8a18e5e43ca13ccfc9d11b449a1c32e60dd97bd93e2885ad6b79b359a71ee715741b68ee3c66f6c3f8297dc56ad8a6e786ac48f99a71305c9744061a25ed10daaad3c3753a4b4d48494d426276edf90547397128251c88d26d4502b4af94457b5beae9160eccde5d16d51d90b78054c17b699af865bce98b7845c076
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90355);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1344");
  script_xref(name:"TRA", value:"TRA-2016-06");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux38417");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-ios-ikev2");

  script_name(english:"Cisco IOS IKEv2 Fragmentation DoS (cisco-sa-20160323-ios-ikev2)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Internet Key Exchange version 2 (IKEv2) subsystem due to
improper handling of fragmented IKEv2 packets. An unauthenticated,
remote attacker can exploit this issue, via specially crafted UDP
packets, to cause the device to reload.

Note that this issue only affects devices with IKEv2 fragmentation
enabled and is configured for any VPN type based on IKEv2.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ios-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9feec3b3");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux38417. Alternatively, apply the workaround as referenced in the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '15.0(2)ED' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.0(2)EH' ) flag++;
if ( ver == '15.0(2)EJ' ) flag++;
if ( ver == '15.0(2)EJ1' ) flag++;
if ( ver == '15.0(2)EK' ) flag++;
if ( ver == '15.0(2)EK1' ) flag++;
if ( ver == '15.0(2)EX' ) flag++;
if ( ver == '15.0(2)EX1' ) flag++;
if ( ver == '15.0(2)EX3' ) flag++;
if ( ver == '15.0(2)EX4' ) flag++;
if ( ver == '15.0(2)EX5' ) flag++;
if ( ver == '15.0(2a)EX5' ) flag++;
if ( ver == '15.0(2)EY' ) flag++;
if ( ver == '15.0(2)EY1' ) flag++;
if ( ver == '15.0(2)EY3' ) flag++;
if ( ver == '15.0(2)EZ' ) flag++;
if ( ver == '15.0(2)SE' ) flag++;
if ( ver == '15.0(2)SE1' ) flag++;
if ( ver == '15.0(2)SE2' ) flag++;
if ( ver == '15.0(2)SE3' ) flag++;
if ( ver == '15.0(2)SE4' ) flag++;
if ( ver == '15.0(2)SE5' ) flag++;
if ( ver == '15.0(2)SE6' ) flag++;
if ( ver == '15.0(2)SE7' ) flag++;
if ( ver == '15.0(2)SE8' ) flag++;
if ( ver == '15.0(2)SE9' ) flag++;
if ( ver == '15.0(2a)SE9' ) flag++;
if ( ver == '15.1(4)GC' ) flag++;
if ( ver == '15.1(4)GC1' ) flag++;
if ( ver == '15.1(4)GC2' ) flag++;
if ( ver == '15.1(4)M' ) flag++;
if ( ver == '15.1(4)M1' ) flag++;
if ( ver == '15.1(4)M10' ) flag++;
if ( ver == '15.1(4)M2' ) flag++;
if ( ver == '15.1(4)M3' ) flag++;
if ( ver == '15.1(4)M3a' ) flag++;
if ( ver == '15.1(4)M4' ) flag++;
if ( ver == '15.1(4)M5' ) flag++;
if ( ver == '15.1(4)M6' ) flag++;
if ( ver == '15.1(4)M7' ) flag++;
if ( ver == '15.1(4)M8' ) flag++;
if ( ver == '15.1(4)M9' ) flag++;
if ( ver == '15.1(3)MR' ) flag++;
if ( ver == '15.1(3)MRA' ) flag++;
if ( ver == '15.1(3)MRA1' ) flag++;
if ( ver == '15.1(3)MRA2' ) flag++;
if ( ver == '15.1(3)MRA3' ) flag++;
if ( ver == '15.1(3)MRA4' ) flag++;
if ( ver == '15.1(2)S' ) flag++;
if ( ver == '15.1(2)S1' ) flag++;
if ( ver == '15.1(2)S2' ) flag++;
if ( ver == '15.1(3)S' ) flag++;
if ( ver == '15.1(3)S0a' ) flag++;
if ( ver == '15.1(3)S1' ) flag++;
if ( ver == '15.1(3)S2' ) flag++;
if ( ver == '15.1(3)S3' ) flag++;
if ( ver == '15.1(3)S4' ) flag++;
if ( ver == '15.1(3)S5' ) flag++;
if ( ver == '15.1(3)S5a' ) flag++;
if ( ver == '15.1(3)S6' ) flag++;
if ( ver == '15.1(1)SG' ) flag++;
if ( ver == '15.1(1)SG1' ) flag++;
if ( ver == '15.1(1)SG2' ) flag++;
if ( ver == '15.1(2)SG' ) flag++;
if ( ver == '15.1(2)SG1' ) flag++;
if ( ver == '15.1(2)SG2' ) flag++;
if ( ver == '15.1(2)SG3' ) flag++;
if ( ver == '15.1(2)SG4' ) flag++;
if ( ver == '15.1(2)SG5' ) flag++;
if ( ver == '15.1(2)SG6' ) flag++;
if ( ver == '15.1(2)SG7' ) flag++;
if ( ver == '15.1(2)SNG' ) flag++;
if ( ver == '15.1(2)SNH' ) flag++;
if ( ver == '15.1(2)SNI' ) flag++;
if ( ver == '15.1(2)SNI1' ) flag++;
if ( ver == '15.1(1)SY' ) flag++;
if ( ver == '15.1(1)SY1' ) flag++;
if ( ver == '15.1(1)SY2' ) flag++;
if ( ver == '15.1(1)SY3' ) flag++;
if ( ver == '15.1(1)SY4' ) flag++;
if ( ver == '15.1(1)SY5' ) flag++;
if ( ver == '15.1(1)SY6' ) flag++;
if ( ver == '15.1(2)SY' ) flag++;
if ( ver == '15.1(2)SY1' ) flag++;
if ( ver == '15.1(2)SY2' ) flag++;
if ( ver == '15.1(2)SY3' ) flag++;
if ( ver == '15.1(2)SY4' ) flag++;
if ( ver == '15.1(2)SY4a' ) flag++;
if ( ver == '15.1(2)SY5' ) flag++;
if ( ver == '15.1(2)SY6' ) flag++;
if ( ver == '15.1(3)T' ) flag++;
if ( ver == '15.1(3)T1' ) flag++;
if ( ver == '15.1(3)T2' ) flag++;
if ( ver == '15.1(3)T3' ) flag++;
if ( ver == '15.1(3)T4' ) flag++;
if ( ver == '15.2(1)E' ) flag++;
if ( ver == '15.2(1)E1' ) flag++;
if ( ver == '15.2(1)E2' ) flag++;
if ( ver == '15.2(1)E3' ) flag++;
if ( ver == '15.2(2)E' ) flag++;
if ( ver == '15.2(2)E1' ) flag++;
if ( ver == '15.2(2)E2' ) flag++;
if ( ver == '15.2(2)E3' ) flag++;
if ( ver == '15.2(2a)E1' ) flag++;
if ( ver == '15.2(2a)E2' ) flag++;
if ( ver == '15.2(3)E' ) flag++;
if ( ver == '15.2(3)E1' ) flag++;
if ( ver == '15.2(3)E2' ) flag++;
if ( ver == '15.2(3)E3' ) flag++;
if ( ver == '15.2(3a)E' ) flag++;
if ( ver == '15.2(3m)E2' ) flag++;
if ( ver == '15.2(4)E' ) flag++;
if ( ver == '15.2(4)E1' ) flag++;
if ( ver == '15.2(2)EB' ) flag++;
if ( ver == '15.2(2)EB1' ) flag++;
if ( ver == '15.2(1)EY' ) flag++;
if ( ver == '15.2(2)EA1' ) flag++;
if ( ver == '15.2(2)EA2' ) flag++;
if ( ver == '15.2(3)EA' ) flag++;
if ( ver == '15.2(4)EA' ) flag++;
if ( ver == '15.2(1)GC' ) flag++;
if ( ver == '15.2(1)GC1' ) flag++;
if ( ver == '15.2(1)GC2' ) flag++;
if ( ver == '15.2(2)GC' ) flag++;
if ( ver == '15.2(3)GC' ) flag++;
if ( ver == '15.2(3)GC1' ) flag++;
if ( ver == '15.2(4)GC' ) flag++;
if ( ver == '15.2(4)GC1' ) flag++;
if ( ver == '15.2(4)GC2' ) flag++;
if ( ver == '15.2(4)GC3' ) flag++;
if ( ver == '15.2(4)M' ) flag++;
if ( ver == '15.2(4)M1' ) flag++;
if ( ver == '15.2(4)M2' ) flag++;
if ( ver == '15.2(4)M3' ) flag++;
if ( ver == '15.2(4)M4' ) flag++;
if ( ver == '15.2(4)M5' ) flag++;
if ( ver == '15.2(4)M6' ) flag++;
if ( ver == '15.2(4)M6a' ) flag++;
if ( ver == '15.2(4)M7' ) flag++;
if ( ver == '15.2(4)M8' ) flag++;
if ( ver == '15.2(4)M9' ) flag++;
if ( ver == '15.2(1)S' ) flag++;
if ( ver == '15.2(1)S1' ) flag++;
if ( ver == '15.2(1)S2' ) flag++;
if ( ver == '15.2(2)S' ) flag++;
if ( ver == '15.2(2)S1' ) flag++;
if ( ver == '15.2(2)S2' ) flag++;
if ( ver == '15.2(4)S' ) flag++;
if ( ver == '15.2(4)S1' ) flag++;
if ( ver == '15.2(4)S2' ) flag++;
if ( ver == '15.2(4)S3' ) flag++;
if ( ver == '15.2(4)S3a' ) flag++;
if ( ver == '15.2(4)S4' ) flag++;
if ( ver == '15.2(4)S4a' ) flag++;
if ( ver == '15.2(4)S5' ) flag++;
if ( ver == '15.2(4)S6' ) flag++;
if ( ver == '15.2(4)S7' ) flag++;
if ( ver == '15.2(2)SNG' ) flag++;
if ( ver == '15.2(2)SNH1' ) flag++;
if ( ver == '15.2(2)SNI' ) flag++;
if ( ver == '15.2(1)SY' ) flag++;
if ( ver == '15.2(1)SY0a' ) flag++;
if ( ver == '15.2(1)SY1' ) flag++;
if ( ver == '15.2(1)SY1a' ) flag++;
if ( ver == '15.2(2)SY' ) flag++;
if ( ver == '15.2(1)T' ) flag++;
if ( ver == '15.2(1)T1' ) flag++;
if ( ver == '15.2(1)T2' ) flag++;
if ( ver == '15.2(1)T3' ) flag++;
if ( ver == '15.2(1)T3a' ) flag++;
if ( ver == '15.2(1)T4' ) flag++;
if ( ver == '15.2(2)T' ) flag++;
if ( ver == '15.2(2)T1' ) flag++;
if ( ver == '15.2(2)T2' ) flag++;
if ( ver == '15.2(2)T3' ) flag++;
if ( ver == '15.2(2)T4' ) flag++;
if ( ver == '15.2(3)T' ) flag++;
if ( ver == '15.2(3)T1' ) flag++;
if ( ver == '15.2(3)T2' ) flag++;
if ( ver == '15.2(3)T3' ) flag++;
if ( ver == '15.2(3)T4' ) flag++;
if ( ver == '15.3(3)M' ) flag++;
if ( ver == '15.3(3)M1' ) flag++;
if ( ver == '15.3(3)M2' ) flag++;
if ( ver == '15.3(3)M3' ) flag++;
if ( ver == '15.3(3)M4' ) flag++;
if ( ver == '15.3(3)M5' ) flag++;
if ( ver == '15.3(3)M6' ) flag++;
if ( ver == '15.3(1)S' ) flag++;
if ( ver == '15.3(1)S1' ) flag++;
if ( ver == '15.3(1)S2' ) flag++;
if ( ver == '15.3(2)S' ) flag++;
if ( ver == '15.3(2)S0a' ) flag++;
if ( ver == '15.3(2)S1' ) flag++;
if ( ver == '15.3(2)S2' ) flag++;
if ( ver == '15.3(3)S' ) flag++;
if ( ver == '15.3(3)S1' ) flag++;
if ( ver == '15.3(3)S2' ) flag++;
if ( ver == '15.3(3)S3' ) flag++;
if ( ver == '15.3(3)S4' ) flag++;
if ( ver == '15.3(3)S5' ) flag++;
if ( ver == '15.3(3)S6' ) flag++;
if ( ver == '15.3(1)T' ) flag++;
if ( ver == '15.3(1)T1' ) flag++;
if ( ver == '15.3(1)T2' ) flag++;
if ( ver == '15.3(1)T3' ) flag++;
if ( ver == '15.3(1)T4' ) flag++;
if ( ver == '15.3(2)T' ) flag++;
if ( ver == '15.3(2)T1' ) flag++;
if ( ver == '15.3(2)T2' ) flag++;
if ( ver == '15.3(2)T3' ) flag++;
if ( ver == '15.3(2)T4' ) flag++;
if ( ver == '15.4(1)CG' ) flag++;
if ( ver == '15.4(1)CG1' ) flag++;
if ( ver == '15.4(2)CG' ) flag++;
if ( ver == '15.4(3)M' ) flag++;
if ( ver == '15.4(3)M1' ) flag++;
if ( ver == '15.4(3)M2' ) flag++;
if ( ver == '15.4(3)M3' ) flag++;
if ( ver == '15.4(3)M4' ) flag++;
if ( ver == '15.4(1)S' ) flag++;
if ( ver == '15.4(1)S1' ) flag++;
if ( ver == '15.4(1)S2' ) flag++;
if ( ver == '15.4(1)S3' ) flag++;
if ( ver == '15.4(1)S4' ) flag++;
if ( ver == '15.4(2)S' ) flag++;
if ( ver == '15.4(2)S1' ) flag++;
if ( ver == '15.4(2)S2' ) flag++;
if ( ver == '15.4(2)S3' ) flag++;
if ( ver == '15.4(2)S4' ) flag++;
if ( ver == '15.4(3)S' ) flag++;
if ( ver == '15.4(3)S1' ) flag++;
if ( ver == '15.4(3)S2' ) flag++;
if ( ver == '15.4(3)S3' ) flag++;
if ( ver == '15.4(3)S4' ) flag++;
if ( ver == '15.4(1)T' ) flag++;
if ( ver == '15.4(1)T1' ) flag++;
if ( ver == '15.4(1)T2' ) flag++;
if ( ver == '15.4(1)T3' ) flag++;
if ( ver == '15.4(1)T4' ) flag++;
if ( ver == '15.4(2)T' ) flag++;
if ( ver == '15.4(2)T1' ) flag++;
if ( ver == '15.4(2)T2' ) flag++;
if ( ver == '15.4(2)T3' ) flag++;
if ( ver == '15.4(2)T4' ) flag++;
if ( ver == '15.5(3)M' ) flag++;
if ( ver == '15.5(3)M0a' ) flag++;
if ( ver == '15.5(3)M1' ) flag++;
if ( ver == '15.5(1)S' ) flag++;
if ( ver == '15.5(1)S1' ) flag++;
if ( ver == '15.5(1)S2' ) flag++;
if ( ver == '15.5(1)S3' ) flag++;
if ( ver == '15.5(2)S' ) flag++;
if ( ver == '15.5(2)S1' ) flag++;
if ( ver == '15.5(2)S2' ) flag++;
if ( ver == '15.5(3)S' ) flag++;
if ( ver == '15.5(3)S0a' ) flag++;
if ( ver == '15.5(3)S1' ) flag++;
if ( ver == '15.5(3)S1a' ) flag++;
if ( ver == '15.5(3)SN' ) flag++;
if ( ver == '15.5(1)T' ) flag++;
if ( ver == '15.5(1)T1' ) flag++;
if ( ver == '15.5(1)T2' ) flag++;
if ( ver == '15.5(1)T3' ) flag++;
if ( ver == '15.5(2)T' ) flag++;
if ( ver == '15.5(2)T1' ) flag++;
if ( ver == '15.5(2)T2' ) flag++;
if ( ver == '15.6(1)T0a' ) flag++;

# Check that IKEv2 fragmentation or IKEv2 is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv2 fragmentation
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if ("crypto ikev2 fragmentation" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # Check for condition 2, IKEv2 is running
  if (flag)
  {
    flag = 0;

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        ) flag = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }

    if (!flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        ) flag = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux38417' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
