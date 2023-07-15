#TRUSTED 0fa1ea0b41fe0bddb07d2d986652e445a544d273a7bffb439b1942fffd85e5544a720df5f9a4c82dd378a5c234a05dffef75761b4bd90e3130e2b51114c5ae618ce543ef04fa674bb9311a431ae93fe1b9b2784f74d73a86f0e098b1c7994bb7ce558690b54c649b443f023f0f25690dddf6ce189e40e2232792d5bdf943c2f06a0f617de2d9451ad45e40a46c1b39c81e5b87cd5666ea368d5b5b25f8e61df640aa3e6568f899579e8a996ecc9951a86715d472344155e4d53fe2277a7467eae747610ce699757fa251815c045974d3336ef5562950445ddd7045a79ef3a5f3681842a28d4c57f460019cd38bc214243d69a583e5d62fbff935e62674a7b6ea94878aefdf0b564328ed1da875eba405f1b3d90fde7c9bc2a9a43edf779c17e65d9ca9662e0398e76b7a3c8baf65491d1bb194513f7bfb9ec4d84b19b46d1683c7c775ce44db9164bd0b14ba94b91e075648a8044bb5838e41484cd06e4e69f72439ede6ef19923cbb76182b72a174b58726d68b6ea8437d938b604732426080fa0d67a05c73dc3a9e8ef26cdb6bb1218dc58d34b37943e335bfafe4730789fd06a727fd0881dea7dc5ef7492ff5de89fcb1b9c031ac2fec95118b182b48411e4a545ba0a61258db1482a4d73613f0edc2d1fe613b4ac1d65d96375f98d62d049bb79b8e9016937c0670ca0dec6ede81a64c4d82578f7638a9a9669c2ec5dcbe
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90353);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2016-1348");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus55821");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-dhcpv6");

  script_name(english:"Cisco IOS DHCPv6 Relay Message Handling DoS (cisco-sa-20160323-dhcpv6)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the DHCPv6 Relay feature due to improper validation of DHCPv6 relay
messages. An unauthenticated, remote attacker can exploit this issue,
via a crafted DHCPv6 relay message, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?239272f7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus55821.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1348");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ( ver == '15.0(1)SY3' ) flag++;
if ( ver == '15.0(1)SY4' ) flag++;
if ( ver == '15.0(1)SY5' ) flag++;
if ( ver == '15.0(1)SY6' ) flag++;
if ( ver == '15.0(1)SY7' ) flag++;
if ( ver == '15.0(1)SY7a' ) flag++;
if ( ver == '15.0(1)SY8' ) flag++;
if ( ver == '15.0(1)SY9' ) flag++;
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
if ( ver == '15.2(3a)E' ) flag++;
if ( ver == '15.2(3m)E2' ) flag++;
if ( ver == '15.2(3m)E3' ) flag++;
if ( ver == '15.2(4)E' ) flag++;
if ( ver == '15.2(2)EB' ) flag++;
if ( ver == '15.2(2)EB1' ) flag++;
if ( ver == '15.2(1)EY' ) flag++;
if ( ver == '15.2(2)EA1' ) flag++;
if ( ver == '15.2(2)EA2' ) flag++;
if ( ver == '15.2(3)EA' ) flag++;
if ( ver == '15.2(4)EA' ) flag++;
if ( ver == '15.2(1)S' ) flag++;
if ( ver == '15.2(1)S1' ) flag++;
if ( ver == '15.2(1)S2' ) flag++;
if ( ver == '15.2(2)S' ) flag++;
if ( ver == '15.2(2)S0a' ) flag++;
if ( ver == '15.2(2)S0c' ) flag++;
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
if ( ver == '15.3(1)S' ) flag++;
if ( ver == '15.3(1)S1' ) flag++;
if ( ver == '15.3(1)S2' ) flag++;
if ( ver == '15.3(2)S' ) flag++;
if ( ver == '15.3(2)S0a' ) flag++;
if ( ver == '15.3(2)S1' ) flag++;
if ( ver == '15.3(2)S2' ) flag++;
if ( ver == '15.3(3)S' ) flag++;
if ( ver == '15.3(3)S1' ) flag++;
if ( ver == '15.3(3)S1a' ) flag++;
if ( ver == '15.3(3)S2' ) flag++;
if ( ver == '15.3(3)S3' ) flag++;
if ( ver == '15.3(3)S4' ) flag++;
if ( ver == '15.3(3)S5' ) flag++;
if ( ver == '15.3(3)S6' ) flag++;
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

# Check for DHCPv6 Relay
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_interface", "show ipv6 dhcp interface");
  if (check_cisco_result(buf))
  {
    if ("is in relay mode" >< buf) flag = 1;
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
      '\n  Cisco bug ID      : CSCus55821' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
