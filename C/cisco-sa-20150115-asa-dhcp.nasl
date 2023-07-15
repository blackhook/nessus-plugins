#TRUSTED 8d1173067a3d57ce69aee323a54efb4cb6622ea1c9e4360602e4c1fc800440ddb78f2e58170be8354db0593298d77d260d1afb32df1197c3e7bfa406a2a96e125ef68a201e1670bf84aa7844f7975605de78e319d404738582807868b20bd015527f9262348254791549f7384ea2acfb202a2854c9db2f2d4a5a08889eece5fb2ea30a9abb936de054b07d17a1fdaad89807df1e3da4409d8ab4875b80d374bea5d95186c2a1c974e51272e7efeeb894e54744628568795890762246afda6822be3eace33d0175df06620bd8df70425426e5e157e73293f09e85e71cdd17fca89b8c04f015c24ba61b0d3780fb1b3208e9b7e447325ae7332faaacdd8736e57baca84aceee99bfeeb6daf3d0eee4b7c40e35079b2c69bc83672d77d3beac3f6266e06ad266807937277b6e0b80844c3a8e56973082889bac5859b9bdeb7a0434ac6f35cb35b7d7e26ad0dfe3a7d944c71b16c3ed87c05688e164aea1801b9a0cb779d6c8274db5c638af729638d38b677ba352ba4db74440921ae526263b09b8a4467f6087c58ed51a47c73d9c3748813a57755888e18f073394530c7bbd9b1192843f067ed1feaecd1042236e99ef93d9b322aad63e7d6f9567b77354fa43e72537c4583bbbef6d736a668b3cd104a8aeddb385d295614824e64aa755c31d58c8d319ade614c973ad6fff743526231a04b9ee06bf3a3549cd122efbe8fc13ef
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86675);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-0578");
  script_bugtraq_id(72718);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur45455");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150115-asa-dhcp");

  script_name(english:"Cisco ASA DHCPv6 Relay Function DHCP Packet Handling DoS (CSCur45455)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) device is affected
by a denial of service vulnerability due to improper validation of
DHCPv6 packets by the DHCPv6 relay function. An unauthenticated,
remote attacker can exploit this, via specially crafted DHCPv6
packets, to cause a device reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150115-asa-dhcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f150f84a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCur45455.
Alternatively, disable the DHCPv6 relay feature.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0578");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Affected :
# Cisco Adaptive Security Virtual Appliance (ASAv)
# Cisco ASA 1000V Cloud Firewall
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
# Cisco ASA Services Module for Cisco 7600 Series Routers
if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V'
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 or 1000V");

fixed_ver = NULL;

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.37)"))
  fixed_ver = "9.0(4)37";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.21)"))
  fixed_ver = "9.1(5)21";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(2)"))
  fixed_ver = "9.3(2)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if DHCP6 relay is in play
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-ipv6-dhcprelay", "show running-config ipv6 dhcprelay");
  if (check_cisco_result(buf))
  {
    if ("ipv6 dhcprelay enable outside" >< buf) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCP6 relaying is not enabled");
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
