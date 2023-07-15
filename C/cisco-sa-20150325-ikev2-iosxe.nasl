#TRUSTED 7987816d5ebd44c21ff0cf2fd089fba013164b6f2dc2c247c90ba4b59bb7f58eeb18ce8423f22a2adeaae9b67af9b0334d23116e17369f82ddc775276af6c8c6cab6fba80d59c962057201f5d4d2d2b7aad6f2eaab31a6b0dd3269018ce10aaccdf44d1994d7b7034de7c05a68087508495d1862c970587a1cfc71af8c59970fc98d52bc82642a6e01c5a70f959d68fdac915f5cfbc87967473de16eb5a144c11a9db7d76420fff193eadb95c9486555d2d10ec1dbe0c39fc77200572b07d0a77970c06c97761bb90a71a1f259109e76f58c3cde867377115be24224b4b042df7d31423c9f5d69111162922fbbda13c74f1ffc02fc0910c14c6d75ba7510aa36cd751bff9bc88d17d553f3d3f0a5ab0a9c21db50de94c402fc2735160f854a7af808f4589d14c4ad4be1138f29c8d164b2c3f390d52bdbc752fb033146ede5e76fc6cff06a158ced635945b17319e41aba6b08ed465eeaabedc4de6c874950bca745aa7f0950c8a33514604b39cca5c6df019ec59eacb3115a0efd910ea04043ed6fcad2df7266406116c3b647e6d177a4af687ff6b1e8f5bbc21330c6e9efd746903707a37d3b99d475879a2f359956b6dadf339ce501cd3c58c85d4b003ccd2d98e2f349856c5f939bc3e0f53ae87c3a2335334c65489f788398db0c03dd7eb910f754b8f29c90371569f92846c5bfec2841dcd34d75c122f6da4e7fe36d9d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82575);
  script_version("1.17");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0642", "CVE-2015-0643");
  script_bugtraq_id(73333);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum36951");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo75572");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-ikev2");

  script_name(english:"Cisco IOS XE IKEv2 DoS (cisco-sa-20150325-ikev2)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Internet Key Exchange version 2 (IKEv2) subsystem
due to improper handling of specially crafted IKEv2 packets. A remote,
unauthenticated attacker can exploit this issue to cause a device
reload or exhaust memory resources.

Note that this issue only affects devices with IKEv1 or ISAKMP
enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10464ee0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37815");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37816");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

fix = '';
flag = 0;

# Check for vuln version
if (
  version =~ "^2\.[56]([^0-9]|$)" ||
  version =~ "^3\.2(\.[0-9]+)?S([^EGQ]|$)" ||
  version =~ "^3\.([1-9]|11)(\.[0-9]+)?S([^EGQ]|$)" ||
  version =~ "^3\.12(\.[0-2])?S([^EG]|$)"
)
{
  fix = "3.12.3S";
  flag++;
}

if(
  version =~ "^3\.10(\.[0-4])?S([^EG]|$)"
)
{
  fix = "3.10.5S";
  flag++;
}

if (
  version =~ "^3\.13(\.[01])?S([^EG]|$)"
)
{
  fix = "3.13.2S";
  flag++;
}

if (
  version =~ "^3\.6(\.[0-4])?E"
)
{
  fix = "3.6.5E";
  flag++;
}

if (
  version =~ "^3\.2(\.[0-9]+)?SE$" ||
  version =~ "^3\.3(\.[0-9]+)?[SE|SG|XO]" ||
  version =~ "^3\.4(\.[0-9]+)?SG" ||
  version =~ "^3\.5(\.[0-9]+)?E" ||
  version =~ "^3\.7(\.0)?E"
)
{
  fix = "3.7.1E";
  flag++;
}

# Check that IKEv1 or ISAKMP is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";

  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
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

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s500\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s848\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s4500\s", string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (fix && flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCum36951 and CSCuo75572' +
      '\n  Installed release : ' + version +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
